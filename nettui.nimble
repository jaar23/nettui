# Package

version       = "0.1.0"
author        = "jaar23"
description   = "Network manager running in terminal ui mode"
license       = "GPL-2.0-or-later"
srcDir        = "src"
bin           = @["nettui"]


# Dependencies

requires "nim >= 2.0.0"
requires "tui_widget >= 0.1.3"