/*
* Author: Balu G <bagajjal@microsoft.com>
*
* This file contains the conpty related functions.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions
* are met:
*
* 1. Redistributions of source code must retain the above copyright
* notice, this list of conditions and the following disclaimer.
* 2. Redistributions in binary form must reproduce the above copyright
* notice, this list of conditions and the following disclaimer in the
* documentation and/or other materials provided with the distribution.
*
* THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
* IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
* OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
* IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
* INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
* NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
* DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
* THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
* THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "Debug.h"
#include "inc\fcntl.h"
#include "misc_internal.h"
#include "signal_internal.h"

// Return Value: 0 for success, -1 for failure
int
CreateConPty(const wchar_t *cmdline,
	const unsigned short width,
	const unsigned short height,
	HANDLE const hInput,
	HANDLE const hOutput,	
	HANDLE const tty_sighandle,
	PROCESS_INFORMATION* const piPty)
{
	wchar_t system32_path[PATH_MAX] = { 0, };

	SetHandleInformation(tty_sighandle, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);

	wchar_t conhostCmdline[8191] = { 0, }; // msdn	
	wchar_t *cmd_fmt = L"%ls\\conhost.exe --headless --width %d --height %d --signal 0x%x -- %ls";
	
	if (!GetSystemDirectoryW(system32_path, PATH_MAX))
		fatal("unable to retrieve system32 path");
	
	_snwprintf_s(conhostCmdline,
		_countof(conhostCmdline),
		_countof(conhostCmdline),
		cmd_fmt,
		system32_path,
		width,
		height,
		tty_sighandle,
		cmdline);
	
	STARTUPINFOW si;
	memset(&si, 0, sizeof(STARTUPINFOW));
	si.cb = sizeof(STARTUPINFOW);
	si.hStdInput = hInput;
	si.hStdOutput = hOutput;	
	si.hStdError = hOutput;
	si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESIZE | STARTF_USECOUNTCHARS;

	debug3("pty commandline: %ls", conhostCmdline);

	/* 
	 * process CTRL+C input.
	 * Child processes will inherit this behavior.
	 */
	SetConsoleCtrlHandler(NULL, FALSE);
	if (0 == CreateProcessW(NULL, conhostCmdline, NULL, NULL, TRUE, 0, NULL, NULL, &si, piPty)) {
		debug("%s - failed to execute %ls, error:%d", __func__, conhostCmdline, GetLastError());
		errno = EOTHER;
		return -1;
	}

	/* disable Ctrl+C hander in this process*/
	SetConsoleCtrlHandler(NULL, TRUE);

	return 0;
}

int is_conpty_supported()
{
	/* TODO - put conditional logic in here that determines if conpty is supported */
	return 0;
}

int exec_command_with_pty(int * pid, wchar_t* cmd, int in, int out, int err, unsigned int col, unsigned int row, int ttyfd)
{
	PROCESS_INFORMATION pi;
	STARTUPINFOW si;	
	wchar_t pty_cmdline[MAX_CMD_LEN] = { 0, };
	int ret = -1;
	HANDLE ttyh = (HANDLE)w32_fd_to_handle(ttyfd);

	memset(&si, 0, sizeof(STARTUPINFO));
	si.cb = sizeof(STARTUPINFO);
	si.dwXSize = 5;
	si.dwYSize = 5;
	si.dwXCountChars = col;
	si.dwYCountChars = row;
	si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESIZE | STARTF_USECOUNTCHARS;

	si.hStdInput = (HANDLE)w32_fd_to_handle(in);
	si.hStdOutput = (HANDLE)w32_fd_to_handle(out);
	si.hStdError = (HANDLE)w32_fd_to_handle(err);
	si.lpDesktop = NULL;

	if (is_conpty_supported())
		return CreateConPty(cmd, (short)si.dwXCountChars, (short)si.dwYCountChars, si.hStdInput, si.hStdOutput, ttyh, &pi);

	/* launch via  "ssh-shellhost" -p command*/

	_snwprintf_s(pty_cmdline, MAX_CMD_LEN, MAX_CMD_LEN, L"\"%ls\\ssh-shellhost.exe\" ---pty %ls", __wprogdir, cmd);
	/* 
	 * In PTY mode, ssh-shellhost takes stderr as control channel
	 * TODO - fix this and pass control channel pipe as a command line parameter
	 */
	si.hStdError = ttyh;
	debug3("pty commandline: %ls", pty_cmdline);

	if (CreateProcessW(NULL, pty_cmdline, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
		if (register_child(pi.hProcess, pi.dwProcessId) == -1) {
			TerminateProcess(pi.hProcess, 0);
			CloseHandle(pi.hProcess);
			goto done;
		}
		CloseHandle(pi.hThread);
	}
	else {
		debug("%s - failed to execute %ls, error:%d", __func__, pty_cmdline, GetLastError());
		errno = EOTHER;
		goto done;
	}
	*pid = pi.dwProcessId;
	ret = 0;

done:
	return ret;
}