FROM python:3.12-slim
WORKDIR /service
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
COPY scripts ./scripts
RUN useradd --system --uid 10001 fame
USER fame
EXPOSE 8769
CMD ["uvicorn","app.main:app","--host","0.0.0.0","--port","8769"]
