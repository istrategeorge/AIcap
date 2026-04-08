import openai

def generate_text():
    api_key = "sk-1234567890abcdef1234567890abcdef"
    response = openai.ChatCompletion.create(
        model="gpt-4-turbo",
        messages=[{"role": "user", "content": "Hello!"}]
    )
    return response
