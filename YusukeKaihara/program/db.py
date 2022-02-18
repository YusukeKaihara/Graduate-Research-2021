import shelve

def getDatabase():

    path = "../database/database.db"
    return shelve.open(path, writeback=True)

def closeDatabase(db):

    db.close()

