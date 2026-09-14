import { FileAdapter } from "./file-adapter.js";

export class CursorAdapter extends FileAdapter {
  constructor() {
    super("Cursor", [".cursor/mcp.json","cursor.mcp.json",".cursor/mcp-servers.json"]);
  }
}
