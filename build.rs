use std::io;

fn main() -> io::Result<()> {
    if std::env::var("CARGO_CFG_TARGET_OS").unwrap() == "windows" {
        let mut res = winres::WindowsResource::new();
        res.set_icon("icon.ico");
        res.set("FileDescription", "Defenders Clipboard - Clipboard-based IOC triage and OSINT lookup tool for SOC analysts");
        res.set("ProductName", "Defenders Clipboard");
        res.set("OriginalFilename", "defenders_clipboard.exe");
        res.set("ProductVersion", "1.1.0.0");
        res.set("FileVersion", "1.1.0.0");
        res.set_manifest(r#"
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="asInvoker" uiAccess="false"/>
      </requestedPrivileges>
    </security>
  </trustInfo>
</assembly>
"#);

        res.compile()?;
    }
    Ok(())
}