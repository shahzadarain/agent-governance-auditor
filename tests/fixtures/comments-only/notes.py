"""Notes on agent frameworks.

    from crewai import Agent, Crew
    import openai
    client.chat.completions.create(model="x", tools=[run_shell])
"""

# import langgraph
# from langchain.agents import AgentExecutor
# agent = create_react_agent(model, tools=[transfer_funds], interrupt_before=["tools"])

EXAMPLE = "from agents import Agent, Runner; Runner.run_sync(Agent(name='x', tools=[pay]))"
SNIPPET = '''
import autogen
from pydantic_ai import Agent
subprocess.run(command, shell=True)
'''


def word_count(text):
    # eval(text) would be a bad idea; this comment must not count as code.
    return len(text.split())
