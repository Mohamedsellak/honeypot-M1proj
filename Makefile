.PHONY: up down logs attack test lint sast dataset clean

up:            ## Lance toute la stack
	docker compose up --build -d
	docker compose ps

down:          ## Arrete la stack
	docker compose down

logs:          ## Suit les logs des conteneurs
	docker compose logs -f

attack:        ## Lance toutes les attaques de validation
	bash attacks/run_all.sh

test:          ## Tests unitaires
	python datasets/gen_dataset.py && pytest -q

lint:          ## Ruff
	ruff check .

sast:          ## Bandit
	bandit -r honeypots analyzer common shipper -ll -x tests

dataset:       ## Genere rockyou-top1000.txt
	python datasets/gen_dataset.py

clean:         ## Nettoie volumes + logs
	docker compose down -v
	rm -rf logs/*.jsonl data/*.db
