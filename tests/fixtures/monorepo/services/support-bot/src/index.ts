import { Agent, run, tool } from '@openai/agents';
import { z } from 'zod';

const getStatus = tool({
  name: 'get_status',
  description: 'Return the status page summary.',
  parameters: z.object({}),
  execute: async () => 'all systems normal',
});

const agent = new Agent({
  name: 'Support bot',
  instructions: 'Answer support questions.',
  tools: [getStatus],
});

export async function main(question: string) {
  const result = await run(agent, question, { maxTurns: 5 });
  return result.finalOutput;
}
