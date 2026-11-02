STAGE_COMPOSE = PREDICTION_CONFIG=./docker/server.toml \
	API_PORT=3100 WEB_PORT=8081 \
	docker compose --project-name prediction-demo-stage --file compose.yml

.PHONY: stage-up stage-logs stage-ps stage-down

stage-up:
	$(STAGE_COMPOSE) up --no-build --pull always --detach --wait --wait-timeout 600

stage-logs:
	$(STAGE_COMPOSE) logs --follow --tail=100

stage-ps:
	$(STAGE_COMPOSE) ps

stage-down:
	$(STAGE_COMPOSE) down
