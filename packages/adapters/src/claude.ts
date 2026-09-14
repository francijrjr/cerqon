import { FileAdapter } from "./file-adapter.js";

export class ClaudeDesktopAdapter extends FileAdapter {
  constructor() {
    super("Claude Desktop", ["claude_desktop_config.json","claude-desktop-config.json","claude_desktop.json"]);
  }
}
