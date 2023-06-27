const sqlite = require('sqlite-async');

const genPass = () => {
    // return crypto.randomBytes(5).toString('hex');
    return 'admin';
}

class Database {
    constructor(db_file) {
        this.db_file = db_file;
        this.db = undefined;
    }

    async connect() {
        this.db = await sqlite.open(this.db_file);
    }


    async migrate() {
        var username = process.env.admin_username
        var password = process.env.admin_password

        // Users Table Init
        this.db.exec(`
        DROP TABLE IF EXISTS users;
            CREATE TABLE IF NOT EXISTS users (
                id         INTEGER NOT  NULL PRIMARY KEY AUTOINCREMENT,
                username   VARCHAR(255) NOT NULL UNIQUE,
                password   VARCHAR(255) NOT NULL
            );
            INSERT INTO users (id, username, password) VALUES
                (1, '${username}', '${password}');
        `);

        return;
    }

    // User Functions
    async login(user, pass) {
        return new Promise(async(resolve, reject) => {
            try {
                let stmt = await this.db.prepare('SELECT * FROM users WHERE username = ? and password = ?');
                resolve(await stmt.get(user, pass));
            } catch (e) {
                reject(e);
            }
        });
    }

    async register(user, pass) {
      return new Promise(async(resolve, reject) => {
          try {
              let stmt = await this.db.prepare('insert into users (username, password) values (?, ?)');
              resolve(await stmt.get(user, pass));
          } catch (e) {
              reject(e);
          }
      });
  }

   async user_exists(user) {
        return new Promise(async (resolve, reject) => {
            try {
                let stmt = await this.db.prepare('SELECT username FROM users WHERE username = ?');
                let row = await stmt.get(user);
                resolve(row !== undefined);
            } catch(e) {
                reject(e);
            }
        });
    }


}

module.exports = Database;