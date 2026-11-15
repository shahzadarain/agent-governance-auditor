// Docs assistant: answers questions from the documentation service and can
// email a summary. Middling posture on purpose; see the README.
import { openai } from '@ai-sdk/openai';
import { generateText, tool } from 'ai';
import { z } from 'zod';

const DOCS_API = process.env.DOCS_API_URL ?? 'http://localhost:8787';
const MAIL_API = process.env.MAIL_API_URL ?? 'http://localhost:8788';

const SearchResult = z.object({
  hits: z.array(z.object({ title: z.string(), url: z.string() })).max(10),
});

const tools = {
  searchDocs: tool({
    description: 'Search the product documentation.',
    parameters: z.object({ query: z.string().max(200) }),
    execute: async ({ query }) => {
      const res = await fetch(`${DOCS_API}/search?q=${encodeURIComponent(query)}`);
      const parsed = SearchResult.safeParse(await res.json());
      if (!parsed.success) {
        throw new Error('search returned an unexpected shape');
      }
      return parsed.data;
    },
  }),
  sendEmail: tool({
    description: 'Email a summary to a colleague.',
    parameters: z.object({ to: z.string().email(), subject: z.string().max(120), body: z.string().max(4000) }),
    execute: async ({ to, subject, body }) => {
      // No human approval and no policy check: the model decides who gets mail.
      const res = await fetch(`${MAIL_API}/send`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', authorization: `Bearer ${process.env.MAIL_API_TOKEN}` },
        body: JSON.stringify({ to, subject, body }),
      });
      return { sent: res.ok };
    },
  }),
};

export async function answer(question: string): Promise<string> {
  const result = await generateText({
    model: openai('gpt-4o-mini'),
    system: 'You answer questions about the product documentation.',
    prompt: question,
    tools,
    maxSteps: 5,
    maxTokens: 800,
  });
  return result.text;
}

if (process.argv[2]) {
  answer(process.argv[2]).then((text) => process.stdout.write(text + '\n'));
}
