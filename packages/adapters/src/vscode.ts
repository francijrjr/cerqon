import { FileAdapter } from "./file-adapter.js";

export class VSCodeRooAdapter extends FileAdapter {
  constructor() {
    super("VS Code / Roo / Cline", [".vscode/mcp.json","roo_cline_mcp_settings.json",".cline/mcp.json",".roo/mcp.json"]);
  }
}
