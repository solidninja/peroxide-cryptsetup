#[deny(warnings)]
#[warn(unused_must_use)]
extern crate libc;
extern crate termios;

use std::io;
use std::io::{Error, ErrorKind, Write};
use std::mem;
use std::os::unix::io::RawFd;
use std::ptr;
use std::time::Duration;

use termios::*;

pub type Result<T> = io::Result<T>;

const INITIAL_PASSWORD_LENGTH: usize = 255;
const STDIN_FD: RawFd = libc::STDIN_FILENO;

/// Prompt for a password from a TTY, returning either the vector of bytes or an error (not a tty, timeout, etc.)
pub fn read_password(prompt: &str, timeout_opt: Option<Duration>) -> Result<Vec<u8>> {
    let is_tty = unsafe { libc::isatty(STDIN_FD) } == 1;
    if !is_tty {
        return Err(Error::new(ErrorKind::BrokenPipe, "stdin is not a tty"));
    }

    // save original and modified attrs
    let term_orig = Termios::from_fd(STDIN_FD)?;
    let mut term_prompt = Termios::from_fd(STDIN_FD)?;

    // write prompt
    io::stdout().write(prompt.as_bytes())?;
    io::stdout().flush()?;

    // turn off echo, but allow newline
    term_prompt.c_lflag &= !ECHO;
    term_prompt.c_lflag |= ECHONL;

    tcsetattr(STDIN_FD, TCSANOW, &term_prompt)?;

    // read password
    let password_res = match timeout_opt {
        Some(timeout) => read_with_timeout(timeout),
        _ => read_stdin(),
    };

    // always try to reset the terminal
    tcsetattr(STDIN_FD, TCSANOW, &term_orig)?;

    password_res
}

fn read_with_timeout(timeout: Duration) -> Result<Vec<u8>> {
    // time interval
    let mut timeval = libc::timeval {
        tv_sec: timeout.as_secs() as libc::time_t,
        tv_usec: timeout.subsec_nanos() as libc::suseconds_t,
    };

    // create fd_set
    let num_fds = STDIN_FD + 1;
    let mut fd_set: libc::fd_set = unsafe { mem::zeroed() };
    unsafe {
        libc::FD_SET(STDIN_FD, &mut fd_set);
    }

    let num_events;
    // loop, retrying on EINTR
    loop {
        let res = unsafe {
            libc::select(
                num_fds,
                &mut fd_set,
                ptr::null_mut(),
                ptr::null_mut(),
                &mut timeval as *mut libc::timeval,
            )
        };

        if res == -1 {
            let err = Error::last_os_error();

            if err.kind() == ErrorKind::Interrupted {
                // according to man page this may lead to timeval being undefined on Linux
                continue;
            } else {
                return Err(err);
            }
        } else {
            num_events = res;
            break;
        }
    }

    if num_events < 1 {
        return Err(Error::new(ErrorKind::TimedOut, "timed out while reading passphrase"));
    }

    read_stdin()
}

fn read_stdin() -> Result<Vec<u8>> {
    let mut pass = String::with_capacity(INITIAL_PASSWORD_LENGTH);
    io::stdin()
        .read_line(&mut pass)
        .map(|_| pass.into_bytes())
        .and_then(|mut buf| {
            if buf.len() > 0 {
                if let Some(b'\n') = buf.pop() {
                    Ok(buf)
                } else {
                    Err(Error::new(ErrorKind::UnexpectedEof, "passphrase should contain a newline at end"))
                }
            } else {
                Err(Error::new(ErrorKind::UnexpectedEof, "passphrase cannot be empty"))
            }
        })
}
