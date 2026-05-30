.PHONY: up down logs demo-protected demo-unprotected scenario1 scenario2 scenario3

up:
	@test -f .env || (cp .env.example .env && echo "Created .env — add your API keys before running again" && exit 1)
	docker compose up --build

down:
	docker compose down -v

logs:
	docker compose logs -f

scenario1:
	curl -s -X POST http://localhost:8081/demo/run-scenario/1 | python3 -m json.tool

scenario2:
	curl -s -X POST http://localhost:8081/demo/run-scenario/2 | python3 -m json.tool

scenario3:
	curl -s -X POST http://localhost:8081/demo/run-scenario/3 | python3 -m json.tool

demo-protected:
	WITH_CRE=true docker compose up --build

demo-unprotected:
	WITH_CRE=false docker compose up --build
