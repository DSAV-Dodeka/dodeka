from databases import Database


async def retrieve_by_id(db: Database, table: str, id_int: int):
    query = f"SELECT * FROM {table} WHERE id = :id"
    record = await db.fetch_one(query, values={"id": id_int})
    return dict(record)


async def upsert_by_id(db: Database, table: str, row: dict):
    r_id = row.pop('id')
    row_keys = ', '.join(row.keys())
    row_values = ', '.join([f"'{val}'" for val in row.values()])
    set_rows = []
    for key, value in row.items():
        set_rows.append(f"{key} = '{value}'")
    set_rows = ', '.join(set_rows)
    query = f"INSERT INTO {table}(id, {row_keys}) VALUES ({r_id}, {row_values})" \
            f"ON CONFLICT (id) DO UPDATE SET" \
            f"  {set_rows};"
    return await db.execute(query=query)
