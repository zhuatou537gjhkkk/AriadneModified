from neo4j import GraphDatabase

# 1. 连接数据库
uri = "neo4j://localhost:7687"
driver = GraphDatabase.driver(uri, auth=("neo4j", "ariadne_neo4j"))

def create_person(tx, name):
    tx.run("CREATE (a:Person {name: $name})", name=name)

def get_person(tx, name):
    result = tx.run("MATCH (a:Person {name: $name}) RETURN a.name AS name", name=name)
    for record in result:
        print(record["name"])

# 2. 执行操作
with driver.session() as session:
    session.execute_write(create_person, "Bob")
    session.execute_read(get_person, "Alice")

# 3. 关闭连接
driver.close()