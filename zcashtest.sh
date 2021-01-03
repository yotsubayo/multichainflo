source ./infra/.env
docker-compose -f ./infra/zcash-compose.yaml up --build -d
echo "Waiting for zcash to boot..."
sleep 30
go test -v ./chain/zcash
docker-compose -f ./infra/zcash-compose.yaml down
echo "Done!"