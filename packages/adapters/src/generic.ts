import { FileAdapter } from "./file-adapter.js";

export class GenericMCPAdapter extends FileAdapter {
  constructor() {
    super("Generic MCP", ["mcp.json","mcp-servers.json","mcp_servers.json",".mcp/config.json","cerqon.agent.json"]);
  }
}
