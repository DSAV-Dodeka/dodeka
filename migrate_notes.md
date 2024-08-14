`tidploy secret db`

postgresql://dodeka:postpost@localhost:3141/dodeka/dodeka

localhost:3141

local URL:
postgresql://dodeka:postpost@localhost:3141/dodeka

tidploy secret db
dodeka:postpost@localhost:3141/dodeka

tidploy run -v db DATABASE_URL --context none -x upgrade.sh -r dodeka

Try:
`psql postgresql://dodeka:postpost@localhost:3141/dodeka`