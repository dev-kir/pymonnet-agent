FROM docker-registry.amirmuz.com/python:3.12-alpine
WORKDIR /app

COPY agent.py .

# install lightweight dependencies and build tools
RUN apk add --no-cache gcc musl-dev linux-headers libffi-dev
RUN pip install psutil docker requests

CMD ["python3", "agent.py"]
