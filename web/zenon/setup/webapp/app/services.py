import requests


class LLM:
    def __init__(
        self,
        model_id: str,
        max_response: int,
        llm_host: str,
        template: str = "{0}",
    ) -> None:
        self.model_id = model_id
        self.max_response = max_response
        self.template = template
        self.api_url = f"http://{llm_host}/models/{self.model_id}"

    def ask(self, question: str):
        prompt = self.template.format(question)
        model_payload = {
            "inputs": prompt,
            "parameters": {
                "best_of": 1,
                "max_new_tokens": self.max_response,
                "do_sample": True,
                "top_k": 5,
                "temperature": 1,
                "seed": 102,
            },
        }
        response = requests.post(self.api_url, json=model_payload)
        print(response.content)
        response = response.json()
        return response[0]["generated_text"][len(prompt) :].strip()
