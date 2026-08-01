#!/usr/bin/env node
// Dedicated entry point so MCP clients can launch the server directly:
//   { "command": "npx", "args": ["-y", "github:AndrewXuTurtle/mcpaudit", "--mcp"] }
// stdout is the JSON-RPC transport, so nothing else may write to it.
import { serve } from '../src/mcp-server.js';
serve();
