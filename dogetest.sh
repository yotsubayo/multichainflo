source ./infra/.env
docker-compose -f ./infra/doge-compose.yaml up --build -d
echo "Waiting for doge to boot..."
sleep 30
go test -v ./chain/dogecoin
docker-compose -f ./infra/doge-compose.yaml down
echo "Done!"