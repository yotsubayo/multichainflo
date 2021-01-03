source ./infra/.env
docker-compose -f ./infra/flo-compose.yaml up --build -d
echo "Waiting for flo to boot..."
sleep 10
go test -v ./chain/flo
docker-compose -f ./infra/flo-compose.yaml down
echo "Done!"