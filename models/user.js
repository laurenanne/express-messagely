/** User class for message.ly */

const db = require("../db");
const ExpressError = require("../expressError");
const bcrypt = require("bcrypt");
const { BCRYPT_WORK_FACTOR } = require("../config");

/** User of the site. */

class User {
  constructor({
    username,
    password,
    first_name,
    last_name,
    phone,
    join_at,
    last_login_at,
  }) {
    this.username = username;
    this.password = password;
    this.first_name = first_name;
    this.last_name = last_name;
    this.phone = phone;
    this.join_at = join_at;
    this.last_login_at = last_login_at;
  }

  /** register new user -- returns
   *    {username, password, first_name, last_name, phone}
   */

  static async register({ username, password, first_name, last_name, phone }) {
    const hashedPassword = await bcrypt.hash(password, BCRYPT_WORK_FACTOR);
    const result = await db.query(
      `INSERT INTO users (
            username,
            password,
            first_name,
            last_name,
            phone,
            join_at,
            last_login_at)
          VALUES ($1, $2, $3, $4, $5, current_timestamp, current_timestamp)
          RETURNING username, password, first_name, last_name, phone`,
      [username, hashedPassword, first_name, last_name, phone]
    );

    return result.rows[0];
  }

  /** Authenticate: is this username/password valid? Returns boolean. */

  static async authenticate(username, password) {
    const result = await db.query(
      `SELECT username, password
      FROM users 
      WHERE username = $1`,
      [username]
    );

    let user = result.rows[0];

    if (user) {
      if ((await bcrypt.compare(password, user.password)) === true) {
        return true;
      }
    }
  }

  /** Update last_login_at for user */

  static async updateLoginTimestamp(username) {
    const result = await db.query(
      `UPDATE users
        SET last_login_at = current_timestamp
        WHERE username = $1
        RETURNING username, last_login_at`,
      [username]
    );

    let user = result.rows[0];

    if (!user) {
      throw new ExpressError(`No such user: ${username}`, 404);
    }
    return user;
  }

  /** All: basic info on all users:
   * [{username, first_name, last_name, phone}, ...] */

  static async all() {
    const result = await db.query(
      `SELECT username, 
              first_name,
              last_name,
              phone
      FROM users`
    );

    let user = result.rows;

    if (!user) {
      throw new ExpressError(`No users`, 404);
    }

    return user;
  }

  /** Get: get user by username
   *
   * returns {username,
   *          first_name,
   *          last_name,
   *          phone,
   *          join_at,
   *          last_login_at } */

  static async get(username) {
    const result = await db.query(
      `SELECT username,
              first_name,
              last_name,
              phone,
              join_at, 
              last_login_at
        FROM users
        WHERE username = $1`,
      [username]
    );

    let user = result.rows[0];

    if (!user) {
      throw new ExpressError(`No such user: ${username}`, 404);
    }

    return user;
  }

  /** Return messages from this user.
   *
   * [{id, to_user, body, sent_at, read_at}]
   *
   * where to_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesFrom(username) {
    const results = await db.query(
      `SELECT 
        m.id,
        m.body, 
        m.sent_at, 
        m.read_at,
        t.username,
        t.first_name,
        t.last_name,
        t.phone
      FROM messages AS m
      JOIN users AS f ON m.from_username = f.username
      JOIN users AS t ON m.to_username =  t.username
      WHERE m.from_username = $1`,
      [username]
    );

    const messages = results.rows;

    let m = messages[0];
    if (!m) {
      throw new ExpressError(`No messages from this user: ${username}`, 404);
    }

    let messFrom = [];

    for (let i = 0; i < messages.length; i++) {
      let mess = {
        id: messages[i].id,
        body: messages[i].body,
        sent_at: messages[i].sent_at,
        read_at: messages[i].read_at,
        to_user: {
          username: messages[i].username,
          first_name: messages[i].first_name,
          last_name: messages[i].last_name,
          phone: messages[i].phone,
        },
      };
      messFrom.push(mess);
    }
    return messFrom;
  }
  /** Return messages to this user.
   *
   * [{id, from_user, body, sent_at, read_at}]
   *
   * where from_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesTo(username) {
    const results = await db.query(
      `SELECT 
        m.id,
        m.body, 
        m.sent_at, 
        m.read_at,
        f.username,
        f.first_name,
        f.last_name,
        f.phone
      FROM messages AS m
      JOIN users AS f ON m.from_username = f.username
      JOIN users AS t ON m.to_username =  t.username
      WHERE m.to_username = $1`,
      [username]
    );

    const messages = results.rows;

    let m = messages[0];
    if (!m) {
      throw new ExpressError(`No messages to this user: ${username}`, 404);
    }

    let messTo = [];
    for (let i = 0; i < messages.length; i++) {
      let mess = {
        id: messages[i].id,
        body: messages[i].body,
        sent_at: messages[i].sent_at,
        read_at: messages[i].read_at,
        from_user: {
          username: messages[i].username,
          first_name: messages[i].first_name,
          last_name: messages[i].last_name,
          phone: messages[i].phone,
        },
      };
      messTo.push(mess);
    }
    return messTo;
  }
}

module.exports = User;
