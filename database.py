import sqlite3

connection = sqlite3.connect("sqlite3.db")

cursor = connection.cursor()

cursor.execute("SELECT count(name) FROM sqlite_master WHERE type='table' AND name='user';")
if cursor.fetchone()[0]==1:
    cursor.execute("DROP TABLE user")

cursor.execute("CREATE TABLE user(username TEXT, password TEXT)")
cursor.execute("INSERT INTO user VALUES ('Alice', 'password')")
cursor.execute("INSERT INTO user VALUES ('Bob', 'password')")
cursor.execute("INSERT INTO user VALUES ('Eve', 'password')")


cursor.execute("CREATE TABLE shared(filepath TEXT, shared_with TEXT, permissions INTEGER)")

connection.commit()
connection.close()