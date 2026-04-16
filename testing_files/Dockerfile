FROM nvcr.io/nvidia/pytorch:24.01-py3

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install transformers accelerate

COPY model_weights/llama-3.safetensors /app/models/
COPY . .

CMD ["python", "serve.py"]
