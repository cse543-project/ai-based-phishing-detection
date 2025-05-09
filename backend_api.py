import asyncio
from openai import OpenAI
from langgraph.graph import StateGraph
from bs4 import BeautifulSoup
from playwright.async_api import async_playwright
from langchain_nvidia_ai_endpoints import ChatNVIDIA
from typing import List, Tuple, Dict, Any, TypedDict
import nest_asyncio
from fastapi import FastAPI, Request
from fastapi.responses import StreamingResponse
import json
import requests
import os
import subprocess
import tempfile
import os
import json
import sys


nest_asyncio.apply()

os.environ["NVIDIA_API_KEY"] = "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"


class AgentState(TypedDict):
    base_url: str
    html: str
    urls: List[str]
    extracted_data: List[Tuple[str, str]]
    summary: List[Tuple[str, str]]
    home_page: str
    home_page_summary: str
    stats: str
    prediction: str
    virus_total: str
    Final: str

def extract_urls(state):
    print(f"Extracting content from {state['base_url']}")

    # Create a temporary Python script
    with tempfile.NamedTemporaryFile(suffix='.py', delete=False, mode='w') as f:
        f.write("""
import sys
from playwright.sync_api import sync_playwright
import json

url = sys.argv[1]
try:
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page()
        response = page.goto(url, timeout=30000)

        if response is None:
            print(json.dumps({"error": "Failed to get response"}))
            sys.exit(1)

        if response.status >= 400:
            print(json.dumps({"error": f"HTTP error {response.status}"}))
            sys.exit(1)

        content = page.content()
        print(json.dumps({"html": content}))
        browser.close()
except Exception as e:
    print(json.dumps({"error": str(e)}))
    sys.exit(1)
        """)
        script_path = f.name

    try:
        # Run the script as a separate process
        result = subprocess.run(
            [sys.executable, script_path, state['base_url']],
            capture_output=True,
            text=True
        )

        # Clean up the temp file
        os.unlink(script_path)

        if result.returncode != 0:
            print(f"Subprocess error: {result.stderr}")
            return {"html": f"Error: Subprocess failed with code {result.returncode}"}

        try:
            output = json.loads(result.stdout)
            # print(output.get('html'))
            if "error" in output:
                return {"html": f"Error: {output['error']}"}
            return {"html": output.get("html", "")}
        except json.JSONDecodeError:
            print(f"Failed to parse output: {result.stdout}")
            return {"html": "Error: Failed to parse subprocess output"}

    except Exception as e:
        print(f"Error running subprocess: {e}")
        return {"html": f"Error: {str(e)}"}


async def get_vt_result(state: AgentState):
    print("Getting results from VirusTotal")
    api_url = "https://www.virustotal.com/api/v3/urls"
    headers = {
        "x-apikey": "25355e6d0f263551e7c2ef88ebaf8e1e82e72d2cc541d38880a72152328561dc"
    }
    data = {"url": state["base_url"]}
    try:
        response = requests.post(api_url, headers=headers, data=data)
        response.raise_for_status()
        json_response = response.json()
        analysis_id = json_response.get('data', {}).get('id')

        if not analysis_id:
            print("Analysis ID not found in response.")
            return {"stats": "Analysis ID not found"}

        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        await asyncio.sleep(10)

        analysis_response = requests.get(analysis_url, headers=headers)
        analysis_response.raise_for_status()
        analysis_json = analysis_response.json()
        stats = analysis_json.get('data', {}).get('attributes', {}).get('stats', {})
        print(stats)
        return {"stats": stats}

    except requests.exceptions.RequestException as e:
        print(f"Request error: {e}")
        return {"stats": f"Request error: {e}"}
    except Exception as e:
        print(f"Error: {e}")
        return {"stats": f"Error during analysis: {e}"}


async def process_with_llm(state: AgentState):
    print("processing the link")

    messages = [
        {"role": "system",
         "content": "Be succinct about the details:\n1. Brand: Score the webpage on a scale of 0-10 for brand accuracy.\n2. Has_Credentials: Does the webpage request sensitive credentials? if yes list them. \n3. Has_Call_To_Action: Does the webpage have calls to action?if yes list them. \n 4. Serves Error: if the site displays error 404, 500 or other errors instead of 200, most likely site is taken down for being a malicious site."},
        {"role": "user", "content": f"{state['html'][:120000]}"}
    ]

    client = OpenAI(
        base_url="https://integrate.api.nvidia.com/v1",
        api_key=os.environ["NVIDIA_API_KEY"]
    )

    completion = client.chat.completions.create(
        model="nvidia/llama-3.3-nemotron-super-49b-v1",
        messages=messages,
        temperature=0.3,
        top_p=0.95,
        max_tokens=1024,
        frequency_penalty=0,
        presence_penalty=0,
        stream=True
    )
    summary = ""
    for chunk in completion:
        if chunk.choices[0].delta.content is not None:
            summary += chunk.choices[0].delta.content
    # summary=response.content
    return {"summary": summary}


async def phishing_prediction(state: AgentState):
    print(f"------- Predicting if the website is a legit or malicious--------------")

    prompt = f"{state['summary']}"
    # print(prompt)
    os.environ["NVIDIA_API_KEY"] = "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"
    client = ChatNVIDIA(
        model="meta/llama-3.1-405b-instruct",
        max_tokens=1024
    )
    messages = [
        {"role": "system", "content": '''Predict the confidence score(in %) of the site being a Phishing site based on rules. start the score from 0%. Don't award any negative confidence score for any of the given criteria.
                                             1. Check if the website is the actual site or is it trying to replicate a big brand (on scale of 10).
                                             2. Check if the site is expecting the user to enter sensitive information.
                                             3. Check if the site is calling the user for some actions like /" click on the link /"
                                             5. Check if the URL tries to imitate some other site or has some weird domains.
                                             6. If the webpage serves HTTP 400 or other error, increase confidence score to 30%.
                                             7. if HTML content is missing, then state not available result.

                                             only output the confidence score in the form
                                             confidence score is <>%.
                                          '''},
        {"role": "user", "content": f"{prompt}"}
    ]
    client = OpenAI(
        base_url="https://integrate.api.nvidia.com/v1",
        api_key=os.environ["NVIDIA_API_KEY"]
    )

    completion = client.chat.completions.create(
        model="nvidia/llama-3.3-nemotron-super-49b-v1",
        messages=messages,
        temperature=0.3,
        top_p=0.95,
        max_tokens=1024,
        frequency_penalty=0,
        presence_penalty=0,
        stream=True
    )
    summary = ""
    for chunk in completion:
        if chunk.choices[0].delta.content is not None:
            summary += chunk.choices[0].delta.content
    print("HTML content based confidence score  : ", summary)

    return {"prediction": summary}


def output(state: AgentState):
    prompt = f"The VirusTotal stats are as follows : {state['stats']}"
    messages = [
        {"role": "system", "content": '''Predict the confidence score(in %) of the site being a Phishing site based on rules, start the score from 0%.
                                             1. if there is even a single entry in malicious column, greatly increase the confidence of being a phishing site.
                                             2. if there is even a single entry in suspicious column, moderately increase the confidence of being a phishing site.
                                             3. if other are entries in other columns, don't add confidence.
                                             4. if there is no entry in all the columns of the stats. It is that of a api error, mention score as 0 with additional tag that virus_total score is not available.
                                             only output the score.
                                          '''},
        {"role": "user", "content": f"{prompt}"}
    ]
    client = OpenAI(
        base_url="https://integrate.api.nvidia.com/v1",
        api_key=os.environ["NVIDIA_API_KEY"]
    )

    completion = client.chat.completions.create(
        model="nvidia/llama-3.3-nemotron-super-49b-v1",
        messages=messages,
        temperature=0.3,
        top_p=0.95,
        max_tokens=1024,
        frequency_penalty=0,
        presence_penalty=0,
        stream=True
    )
    summary = ""
    for chunk in completion:
        if chunk.choices[0].delta.content is not None:
            summary += chunk.choices[0].delta.content
    print("virus_total : ", summary)

    prompt = f'''Virus_total confidence score : {summary}
             Web_page based confidence score : {state['prediction']}


          '''
    messages = [
        {"role": "system", "content": '''Predict the confidence score(in %) of the site being a Phishing site based on rules.
                                             1. you are given confidence score from virus_total
                                             2. you are given confidence score based on webpage content.
                                             if any of the scores are 'N/A', then consider them as 0.
                                             Aggregate both scores, give more priority to the virustotal one.
                                             - if virustotal score is greatly higher than the other score. consider only virustotal score.
                                             - if the difference is not much, use their aggregate giving more priority to VirusTotal score.
                                             - if virustotal score in not available, just give more priority to webpage based score.
                                             only output the confidence score.
                                          '''},
        {"role": "user", "content": f"{prompt}"}
    ]
    client = OpenAI(
        base_url="https://integrate.api.nvidia.com/v1",
        api_key=os.environ["NVIDIA_API_KEY"]
    )

    completion = client.chat.completions.create(
        model="nvidia/llama-3.3-nemotron-super-49b-v1",
        messages=messages,
        temperature=0.6,
        top_p=0.95,
        max_tokens=4096,
        frequency_penalty=0,
        presence_penalty=0,
        stream=True
    )
    summary = ""
    for chunk in completion:
        if chunk.choices[0].delta.content is not None:
            summary += chunk.choices[0].delta.content
    print("Final : ", summary)
    return {"prediction":summary}

def final(state:AgentState):
    prompt = f"Final confidence score : {state['prediction']}"
    client = OpenAI(
        base_url="https://integrate.api.nvidia.com/v1",
        api_key=os.environ["NVIDIA_API_KEY"]
    )
    messages = [
        {"role": "system", "content": '''Only output the confidence score with no additional explanation.
                                            example: Final confidence score is **45%**.
                                            Response: 45.
                                                '''},
        {"role": "user", "content": f"{prompt}"}
    ]
    completion = client.chat.completions.create(
        model="nvidia/llama-3.3-nemotron-super-49b-v1",
        messages=messages,
        temperature=0.6,
        top_p=0.95,
        max_tokens=16,
        frequency_penalty=0,
        presence_penalty=0,
        stream=True
    )
    answer = ""
    for chunk in completion:
        if chunk.choices[0].delta.content is not None:
            answer += chunk.choices[0].delta.content
    print(answer)
    return {"Final": answer}

workflow = StateGraph(AgentState)

workflow.add_node("extract_urls", extract_urls)
workflow.add_node("process_with_llm", process_with_llm)
workflow.add_node("get_vt_result", get_vt_result)
workflow.add_node("phishing_prediction", phishing_prediction)
workflow.add_node("output", output)
workflow.add_node("final",final)


workflow.set_entry_point("extract_urls")
workflow.add_edge("extract_urls", "process_with_llm")
workflow.add_edge("process_with_llm", "phishing_prediction")
workflow.add_edge("phishing_prediction", "get_vt_result")
workflow.add_edge("get_vt_result", "output")
workflow.add_edge("output","final")

langgraph_app = workflow.compile()

app = FastAPI()


@app.post("/analyze")
async def analyze_website(request: Request):
    data = await request.json()
    url = data['url']

    async def generate():
        try:
            # Initial state
            yield json.dumps({"status": "🔍 Extracting page content..."}) + "\n"

            # Run the analysis pipeline
            initial_state = {"base_url": url, "urls": [], "extracted_data": [], "summary": ""}
            result = await langgraph_app.ainvoke(initial_state)

            # Stream intermediate statuses
            yield json.dumps({"status": "🛡️ Checking VirusTotal..."}) + "\n"
            yield json.dumps({"status": "🤖 Analyzing content with AI..."}) + "\n"

            # Final result
            # print("Testing : ")
            final_score = result.get('Final')
            print(final_score)
            yield json.dumps({
                "result": {

                    "final_score": final_score
                }
            }) + "\n"

        except Exception as e:
            yield json.dumps({"error": str(e)}) + "\n"

    return StreamingResponse(generate(), media_type="application/x-ndjson")


# async def run_agent(base_url: str):
#     initial_state = {"base_url": base_url, "urls": [], "extracted_data": [], "summary": ""}
#     return await analyze_website()


# def main():
#     # Use the appropriate event loop policy for Windows
#     test_state = {"base_url": "https://www.12voltdoesit.com/"}
#
#     # Run the extract_urls function using sync api
#     result = extract_urls(test_state)
#     print("Extraction result:", result)


if __name__ == "__main__":
    # main()
    import sys

    # Set the event loop policy for Windows
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
