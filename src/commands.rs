// Copyright 2016 Mozilla Foundation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use client::{
    connect_to_server,
    connect_with_retry,
    ServerConnection,
};
use cmdline::Command;
use compiler::{
    run_input_output,
};
use errors::*;
use log::LogLevel::Trace;
use mock_command::{
    CommandCreatorSync,
    ProcessCommandCreator,
    RunCommand,
};
use number_prefix::{
    binary_prefix,
    Prefixed,
    Standalone,
};
use protobuf::RepeatedField;
use protocol::{
    CacheStats,
    ClientRequest,
    Compile,
    CompileFinished,
    CompileStarted,
    GetStats,
    Shutdown,
    UnhandledCompile,
    ZeroStats,
};
use server;
use std::env;
use std::ffi::{OsStr,OsString};
use std::fs::{File, OpenOptions};
use std::io::{
    self,
    Read,
    Write,
};
#[cfg(unix)]
use std::os::unix::process::ExitStatusExt;
use std::path::{
    Path,
};
use std::process;
use which::which_in;

/// The default sccache server port.
pub const DEFAULT_PORT: u16 = 4226;

/// The number of milliseconds to wait for server startup.
const SERVER_STARTUP_TIMEOUT_MS: u32 = 5000;

/// Possible responses from the server for a `Compile` request.
enum CompileResponse {
    /// The compilation was started.
    CompileStarted(CompileStarted),
    /// The server could not handle this compilation request.
    UnhandledCompile(UnhandledCompile),
}

/// Get the port on which the server should listen.
fn get_port() -> u16 {
    env::var("SCCACHE_SERVER_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_PORT)
}

/// Re-execute the current executable as a background server, and wait
/// for it to start up.
#[cfg(not(windows))]
fn run_server_process() -> Result<()> {
    use libc::{c_int, poll, pollfd, nfds_t, POLLIN, POLLERR};
    use tempdir::TempDir;
    use std::os::unix::io::AsRawFd;
    use std::os::unix::net::UnixListener;

    trace!("run_server_process");
    let tempdir = try!(TempDir::new("sccache")
                       .chain_err(|| "Failed to create temporary directory"));
    let socket_path = tempdir.path().join("sock");
    let listener = try!(UnixListener::bind(&socket_path));
    try!(env::current_exe()
         .and_then(|exe_path| {
             process::Command::new(exe_path)
                 .env("SCCACHE_START_SERVER", "1")
                 .env("SCCACHE_STARTUP_NOTIFY", &socket_path)
                 .env("RUST_BACKTRACE", "1")
                 .spawn()
         })
         .chain_err(|| "Failed to spawn server daemon process"));
    // wait for a connection on the listener using `poll`
    let mut pfds = vec![pollfd {
        fd: listener.as_raw_fd(),
        events: POLLIN | POLLERR,
        revents: 0,
    }];
    loop {
        match unsafe { poll(pfds.as_mut_ptr(), pfds.len() as nfds_t, SERVER_STARTUP_TIMEOUT_MS as c_int) } {
            // Timed out.
            0 => bail!(ErrorKind::ServerStartupTimedOut),
            // Error.
            -1 => {
                let e = io::Error::last_os_error();
                match e.kind() {
                    // We should retry on EINTR.
                    io::ErrorKind::Interrupted => {}
                    //TODO: could chain the error
                    _ => bail!("Failed to start server"),
                }
            }
            // Success.
            _ => {
                if pfds[0].revents & POLLIN == POLLIN {
                    // Ready to read
                    break;
                }
                if pfds[0].revents & POLLERR == POLLERR {
                    // Could give a better error here, I suppose?
                    bail!("Failed to start server");
                }
            }
        }
    }
    // Now read a status from the socket.
    //TODO: when we're using serde, use that here.
    let (mut stream, _) = try!(listener.accept()
                               .chain_err(|| "Failed to start server"));
    let mut buffer = [0; 1];
    try!(stream.read_exact(&mut buffer).chain_err(|| "Failed to start server"));
    if buffer[0] == 0 {
        info!("Server started up successfully");
        Ok(())
    } else {
        //TODO: send error messages over the socket as well.
        let msg = format!("Failed to start server: {}", buffer[0]);
        error!("{}", msg);
        bail!(msg);
    }
}

/// Pipe `cmd`'s stdio to `/dev/null`, unless a specific env var is set.
#[cfg(not(windows))]
fn daemonize() -> Result<()> {
    use daemonize::Daemonize;
    if match env::var("SCCACHE_NO_DAEMON") {
            Ok(val) => val == "1",
            Err(_) => false,
    } {
        Ok(())
    } else {
        Daemonize::new().start()
            .chain_err(|| "Failed to daemonize")
    }
}

/// This is a no-op on Windows.
#[cfg(windows)]
fn daemonize() -> Result<()> { Ok(()) }

#[cfg(not(windows))]
fn redirect_stderr(f: File) -> Result<()> {
    use libc::dup2;
    use std::os::unix::io::IntoRawFd;
    // Ignore errors here.
    unsafe { dup2(f.into_raw_fd(), 2); }
    Ok(())
}

#[cfg(windows)]
fn redirect_stderr(f: File) -> Result<()> {
    use kernel32::SetStdHandle;
    use winapi::winbase::STD_ERROR_HANDLE;
    use std::os::windows::io::IntoRawHandle;
    // Ignore errors here.
    unsafe { SetStdHandle(STD_ERROR_HANDLE, f.into_raw_handle()); }
    Ok(())
}

/// If `SCCACHE_ERROR_LOG` is set, redirect stderr to it.
fn redirect_error_log() -> Result<()> {
    match env::var("SCCACHE_ERROR_LOG") {
        Ok(filename) => OpenOptions::new()
            .create(true)
            .append(true)
            .open(filename)
            .chain_err(|| "Failed to open error log")
            .and_then(redirect_stderr),
        _ => Ok(()),
    }
}

/// Re-execute the current executable as a background server.
///
/// `std::process::Command` doesn't expose a way to create a
/// detatched process on Windows, so we have to roll our own.
/// TODO: remove this all when `CommandExt::creation_flags` hits stable:
/// https://github.com/rust-lang/rust/issues/37827
#[cfg(windows)]
fn run_server_process() -> Result<()> {
    use kernel32;
    use named_pipe::PipeOptions;
    use std::io::Error;
    use std::os::windows::ffi::OsStrExt;
    use std::mem;
    use std::ptr;
    use uuid::Uuid;
    use winapi::minwindef::{TRUE,FALSE,LPVOID,DWORD};
    use winapi::processthreadsapi::{PROCESS_INFORMATION,STARTUPINFOW};
    use winapi::winbase::{CREATE_UNICODE_ENVIRONMENT,DETACHED_PROCESS,CREATE_NEW_PROCESS_GROUP};

    trace!("run_server_process");
    // Create a pipe to get startup status back from the server.
    let pipe_name = format!(r"\\.\pipe\{}", Uuid::new_v4().simple());
    let server = try!(PipeOptions::new(&pipe_name).single()
                      .chain_err(|| "Failed to start server"));
    env::current_exe()
        .and_then(|exe_path| {
            let mut exe = OsStr::new(&exe_path)
                .encode_wide()
                .chain(Some(0u16))
                .collect::<Vec<u16>>();
            // Collect existing env vars + extra into an environment block.
            let mut envp = {
                let mut v = vec!();
                let extra_vars = vec![
                    (OsString::from("SCCACHE_START_SERVER"), OsString::from("1")),
                    (OsString::from("SCCACHE_STARTUP_NOTIFY"), OsString::from(&pipe_name)),
                    (OsString::from("RUST_BACKTRACE"), OsString::from("1")),
                ];
                for (key, val) in env::vars_os().chain(extra_vars) {
                    v.extend(key.encode_wide().chain(Some('=' as u16)).chain(val.encode_wide()).chain(Some(0)));
                }
                v.push(0);
                v
            };
            let mut pi = PROCESS_INFORMATION {
                hProcess: ptr::null_mut(),
                hThread: ptr::null_mut(),
                dwProcessId: 0,
                dwThreadId: 0,
            };
            let mut si: STARTUPINFOW = unsafe { mem::zeroed() };
            si.cb = mem::size_of::<STARTUPINFOW>() as DWORD;
            if unsafe { kernel32::CreateProcessW(exe.as_mut_ptr(),
                                                 ptr::null_mut(),
                                                 ptr::null_mut(),
                                                 ptr::null_mut(),
                                                 FALSE,
                                                 CREATE_UNICODE_ENVIRONMENT | DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP,
                                                 envp.as_mut_ptr() as LPVOID,
                                                 ptr::null(),
                                                 &mut si,
                                                 &mut pi) == TRUE } {
                unsafe {
                    kernel32::CloseHandle(pi.hProcess);
                    kernel32::CloseHandle(pi.hThread);
                }
                Ok(())
            } else {
                //TODO: chain Error::last_os_error()
                bail!("Failed to start server")
            }
        })
        .and_then(|()| {
            // Wait for a connection on the pipe.
            let mut pipe = match try!(server.wait_ms(SERVER_STARTUP_TIMEOUT_MS)
                                      .chain_err(|| "Failed to start server")) {
                Ok(pipe) => pipe,
                Err(_) => bail!(ErrorKind::ServerStartupTimedOut),
            };
            // It would be nice to have a read timeout here.
            let mut buffer = [0; 1];
            try!(pipe.read_exact(&mut buffer)
                 .chain_err(|| "Failed to start server"));
            if buffer[0] == 0 {
                info!("Server started up successfully");
                Ok(())
            } else {
                //TODO: send error messages over the socket as well.
                let msg = format!("Failed to start server: {}", buffer[0]);
                error!("{}", msg);
                bail!(msg);
            }
        })
}

/// Attempt to connect to an sccache server listening on `port`, or start one if no server is running.
fn connect_or_start_server(port: u16) -> Result<ServerConnection> {
    trace!("connect_or_start_server({})", port);
    connect_to_server(port).or_else(|e| {
        if match &e {
            &Error(ErrorKind::Io(ref ioe), _) => {
                match ioe.kind() {
                    io::ErrorKind::ConnectionRefused | io::ErrorKind::TimedOut => true,
                    _ => false,
                }
            }
            _ => false
        } {
            // If the connection was refused we probably need to start
            // the server.
            run_server_process().and_then(|_| connect_with_retry(port))
        } else {
            debug!("Failed to connect to server: {}", e);
            Err(e.into())
        }
    })
}

/// Send a `ZeroStats` request to the server, and return the `CacheStats` request if successful.
pub fn request_zero_stats(mut conn : ServerConnection) -> Result<CacheStats> {
    debug!("request_stats");
    let mut req = ClientRequest::new();
    req.set_zero_stats(ZeroStats::new());
    //TODO: better error mapping
    let mut response = try!(conn.request(req).chain_err(|| "Failed to send zero statistics command to server or failed to receive respone"));
    if response.has_stats() {
        Ok(response.take_stats())
    } else {
        bail!("Unexpected server response!")
    }
}

/// Send a `GetStats` request to the server, and return the `CacheStats` request if successful.
pub fn request_stats(mut conn : ServerConnection) -> Result<CacheStats> {
    debug!("request_stats");
    let mut req = ClientRequest::new();
    req.set_get_stats(GetStats::new());
    //TODO: better error mapping
    let mut response = try!(conn.request(req).chain_err(|| "Failed to send data to or receive data from server"));
    if response.has_stats() {
        Ok(response.take_stats())
    } else {
        bail!("Unexpected server response!")
    }
}

/// Send a `Shutdown` request to the server, and return the `CacheStats` contained within the response if successful.
pub fn request_shutdown(mut conn : ServerConnection) -> Result<CacheStats> {
    debug!("request_shutdown");
    let mut req = ClientRequest::new();
    req.set_shutdown(Shutdown::new());
    //TODO: better error mapping
    let mut response = try!(conn.request(req).chain_err(|| "Failed to send data to or receive data from server"));
    if response.has_shutting_down() {
        Ok(response.take_shutting_down().take_stats())
    } else {
        bail!("Unexpected server response!")
    }
}

/// Print `stats` to stdout.
fn print_stats(stats: CacheStats) -> Result<()> {
    let formatted = stats.get_stats().iter()
        .map(|s| (s.get_name(), if s.has_count() {
            format!("{}", s.get_count())
        } else if s.has_str() {
            s.get_str().to_owned()
        } else if s.has_size() {
            match binary_prefix(s.get_size() as f64) {
                Standalone(bytes) => format!("{} bytes", bytes),
                Prefixed(prefix, n) => format!("{:.0} {}B", n, prefix),
            }
        } else {
            String::from("???")
        }))
        .collect::<Vec<_>>();
    let name_width = formatted.iter().map(|&(n, _)| n.len()).max().unwrap();
    let stat_width = formatted.iter().map(|&(_, ref s)| s.len()).max().unwrap();
    for (name, stat) in formatted {
        println!("{:<name_width$} {:>stat_width$}", name, stat, name_width=name_width, stat_width=stat_width);
    }
    Ok(())
}

/// Send a `Compile` request to the server, and return the server response if successful.
fn request_compile<W: AsRef<Path>, X: AsRef<OsStr>, Y: AsRef<Path>>(conn: &mut ServerConnection, exe: W, args: &Vec<X>, cwd: Y) -> Result<CompileResponse> {
    //TODO: It'd be nicer to send these over as raw bytes.
    let exe = try!(exe.as_ref().to_str().ok_or_else(|| "Bad exe filename"));
    let cwd = try!(cwd.as_ref().to_str().ok_or_else(|| "Bad cwd"));
    let args = args.iter().filter_map(|a| a.as_ref().to_str().map(|s| s.to_owned())).collect::<Vec<_>>();
    if args.is_empty() {
        bail!("Empty commandline");
    }
    let mut req = ClientRequest::new();
    let mut compile = Compile::new();
    compile.set_exe(exe.to_owned());
    compile.set_cwd(cwd.to_owned());
    compile.set_command(RepeatedField::from_vec(args));
    trace!("request_compile: {:?}", compile);
    req.set_compile(compile);
    //TODO: better error mapping?
    let mut response = try!(conn.request(req).chain_err(|| "Failed to send data to or receive data from server"));
    if response.has_compile_started() {
        Ok(CompileResponse::CompileStarted(response.take_compile_started()))
    } else if response.has_unhandled_compile() {
        Ok(CompileResponse::UnhandledCompile(response.take_unhandled_compile()))
    } else {
        bail!("Unexpected response from server")
    }
}

/// Return the signal that caused a process to exit from `status`.
#[cfg(unix)]
#[allow(dead_code)]
fn status_signal(status: process::ExitStatus) -> Option<i32> {
    status.signal()
}

/// Not implemented for non-Unix.
#[cfg(not(unix))]
#[allow(dead_code)]
fn status_signal(_status: process::ExitStatus) -> Option<i32> {
    None
}

/// Handle `response`, the output from running a compile on the server. Return the compiler exit status.
fn handle_compile_finished<T: Write, U: Write>(response: CompileFinished, stdout: &mut T, stderr: &mut U) -> Result<i32> {
    trace!("handle_compile_finished");
    // It might be nice if the server sent stdout/stderr as the process
    // ran, but then it would have to also save them in the cache as
    // interleaved streams to really make it work.
    if response.has_stdout() {
        try!(stdout.write_all(response.get_stdout()));
    }
    if response.has_stderr() {
        try!(stderr.write_all(response.get_stderr()));
    }
    if response.has_retcode() {
        let ret = response.get_retcode();
        trace!("compiler exited with status {}", ret);
        Ok(ret)
    } else if response.has_signal() {
        println!("Compiler killed by signal {}", response.get_signal());
        Ok(-2)
    } else {
        println!("Missing compiler exit status!");
        Ok(-3)
    }
}

/// Handle `response`, the response from sending a `Compile` request to the server. Return the compiler exit status.
///
/// If the server returned `CompileStarted`, wait for a `CompileFinished` and
/// print the results.
///
/// If the server returned `UnhandledCompile`, run the compilation command
/// locally using `creator` and return the result.
fn handle_compile_response<T, U, V, W, X, Y>(mut creator: T,
                                             conn: &mut ServerConnection,
                                             response: CompileResponse,
                                             exe: W,
                                             cmdline: Vec<X>,
                                             cwd: Y,
                                             stdout: &mut U,
                                             stderr: &mut V) -> Result<i32>
    where T: CommandCreatorSync,
          U: Write,
          V: Write,
          W: AsRef<OsStr>,
          X: AsRef<OsStr>,
          Y: AsRef<Path>
{
    match response {
        CompileResponse::CompileStarted(_) => {
            debug!("Server sent CompileStarted");
            // Wait for CompileFinished.
            conn.read_one_response()
                .chain_err(|| "Error reading compile response from server")
                .and_then(|mut res| {
                    if res.has_compile_finished() {
                        trace!("Server sent CompileFinished");
                        handle_compile_finished(res.take_compile_finished(),
                                                stdout, stderr)
                    } else {
                        bail!("Unexpected response from server")
                    }
                })
        }
        CompileResponse::UnhandledCompile(_) => {
            debug!("Server sent UnhandledCompile");
            //TODO: possibly capture output here for testing.
            let mut cmd = creator.new_command_sync(exe.as_ref());
            cmd.args(&cmdline)
                .current_dir(cwd.as_ref());
            if log_enabled!(Trace) {
                trace!("running command: {:?}", cmd);
            }
            run_input_output(cmd, None)
                .chain_err(|| "Failed to run compiler")
                .and_then(|output| {
                    if !output.stdout.is_empty() {
                        try!(stdout.write_all(&output.stdout));
                    }
                    if !output.stderr.is_empty() {
                        try!(stderr.write_all(&output.stderr));
                    }
                    Ok(output.status.code()
                       .unwrap_or_else(|| {
                           /* TODO: this breaks type inference, figure out why
                           status_signal(status)
                           .and_then(|sig : i32| {
                           println!("Compile terminated by signal {}", sig);
                           None
                       });
                            */
                           // Arbitrary.
                          2 
                       }))
                })
        }
    }
}

/// Send a `Compile` request to the sccache server `conn`, and handle the response.
///
/// The first entry in `cmdline` will be looked up in `path` if it is not
/// an absolute path.
/// See `request_compile` and `handle_compile_response`.
pub fn do_compile<T, U, V, W, X, Y>(creator: T,
                                    mut conn: ServerConnection,
                                    exe: W,
                                    cmdline: Vec<X>,
                                    cwd: Y,
                                    path: Option<OsString>,
                                    stdout: &mut U,
                                    stderr: &mut V) -> Result<i32>
    where T: CommandCreatorSync,
U : Write, V : Write, W: AsRef<OsStr>, X: AsRef<OsStr>, Y: AsRef<Path>
{
      trace!("do_compile");
    which_in(exe, path, &cwd)
        .map_err(|_| Error::from_kind(ErrorKind::Msg("Failed to locate compiler binary".to_owned())))
        .and_then(|exe_path| {
            request_compile(&mut conn, &exe_path, &cmdline, &cwd)
                .and_then(|res| handle_compile_response(creator, &mut conn, res, exe_path, cmdline, cwd, stdout, stderr))
        })
}

/// Run `cmd` and return the process exit status.
pub fn run_command(cmd: Command) -> Result<i32> {
    match cmd {
        Command::ShowStats => {
            trace!("Command::ShowStats");
            connect_or_start_server(get_port()).and_then(request_stats).and_then(print_stats).and(Ok(0)).chain_err(|| "Couldn't get stats from server")
        },
        Command::InternalStartServer => {
            trace!("Command::InternalStartServer");
            // Can't report failure here, we're already daemonized, but
            // start server will report failures back to the client over
            // a pipe or unix socket.
            daemonize()
                .and_then(|_| redirect_error_log())
                .and_then(|_| server::start_server(get_port()))
                .and(Ok(0))
        },
        Command::StartServer => {
            trace!("Command::StartServer");
            println!("Starting sccache server...");
            run_server_process()
                .and(Ok(0))
        },
        Command::StopServer => {
            trace!("Command::StopServer");
            println!("Stopping sccache server...");
            connect_to_server(get_port())
                .and_then(request_shutdown)
                .and_then(print_stats)
                .and(Ok(0))
                .chain_err(|| "Couldn't connect to server")
        },
        Command::Compile { exe, cmdline, cwd } => {
            trace!("Command::Compile {{ {:?}, {:?}, {:?} }}", exe, cmdline, cwd);
            connect_or_start_server(get_port())
                .and_then(|conn| do_compile(ProcessCommandCreator, conn, &exe, cmdline, &cwd, env::var_os("PATH"), &mut io::stdout(), &mut io::stderr()))
                .chain_err(|| "Failed to execute compile")
        },
        Command::ZeroStats => {
            trace!("Command::ZeroStats");
            connect_or_start_server(get_port())
                .and_then(request_zero_stats)
                .and_then(print_stats)
                .and(Ok(0))
                .chain_err(|| "Couldn't zero stats on server")
        },
    }
}
