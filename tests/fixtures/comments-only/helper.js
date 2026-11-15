// import { Agent, run } from '@openai/agents';
/* const { McpServer } = require('@modelcontextprotocol/sdk/server/mcp.js'); */
const doc = "import { generateText, tool } from 'ai'; generateText({ tools })";
const tpl = `const OpenAI = require('openai'); new OpenAI().chat.completions.create({ tools: [] })`;

export function shout(text) {
  return text.toUpperCase();
}
