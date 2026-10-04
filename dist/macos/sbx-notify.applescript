-- sbx on a Mac: the application Notification Center shows sbx's notes under.
--
-- macOS attributes a notification to the application that posts it, so a note raised through
-- `osascript` carries Script Editor's name and icon. The installer compiles this script into an
-- application with sbx's own identifier and icon, and `sbx-bridge` hands it each note as a file.
--
-- Only a file the bridge wrote is read: one ending in `.sbxnote` in the bridge's own hand-off
-- directory, which no guest mount reaches. Anything else opened with this application, a file
-- dropped on it included, is left untouched. A note is three lines, the title, the subtitle and
-- the body, already sanitised by the bridge, and the file is removed once it has been raised.

on open theFiles
	set handoff to (POSIX path of (path to home folder)) & ".local/state/sbx/lima/notify-raise/"
	repeat with f in theFiles
		set p to POSIX path of f
		if p starts with handoff and p ends with ".sbxnote" then
			try
				set lines_ to paragraphs of (read (POSIX file p) as «class utf8»)
				set t to ""
				set s to ""
				set b to ""
				if (count of lines_) > 0 then set t to item 1 of lines_
				if (count of lines_) > 1 then set s to item 2 of lines_
				if (count of lines_) > 2 then set b to item 3 of lines_
				if t is not "" then display notification b with title t subtitle s
			end try
			do shell script "rm -f " & quoted form of p
		end if
	end repeat
end open

on run
end run
