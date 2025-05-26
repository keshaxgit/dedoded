const express = require('express');
const { Server } = require('couchbase');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const cors = require('cors');
require('dotenv').config();

// Инициализация Couchbase-кластера
const cluster = new Server.Cluster({
  connectionString: process.env.COUCHBASE_CONNECTION_STRING,
  username: process.env.COUCHBASE_USERNAME,
  password: process.env.COUCHBASE_PASSWORD
});

cluster.authenticate(process.env.COUCHBASE_USERNAME, process.env.COUCHBASE_PASSWORD);
const bucket = cluster.openBucket(process.env.COUCHBASE_BUCKET_NAME);

const app = express();
const PORT = process.env.PORT || 8000;

// Средства безопасности
app.use(cors());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json());

// Роуты
app.post('/register', async (req, res) => {
  const { login, email, password, fullName, gender } = req.body;

  // Проверка наличия всех полей
  if (!login || !email || !password || !fullName || !gender) return res.status(400).send("Все поля обязательны");

  try {
    // Хэширование пароля перед сохранением
    const hashedPassword = await bcrypt.hash(password, 10);

    // Сохранение нового пользователя
    await bucket.upsert(login, {
      type: 'user',
      email,
      fullName,
      gender,
      password: hashedPassword
    });

    res.sendStatus(201); // Успешное создание аккаунта
  } catch(err) {
    console.error(err.message);
    res.status(500).send("Ошибка при создании аккаунта");
  }
});

app.post('/login', async (req, res) => {
  const { login, password } = req.body;

  if (!login || !password) return res.status(400).send("Логин и пароль необходимы");

  try {
    const userDoc = await bucket.get(login);
    const userData = userDoc.value;

    // Проверяем совпадение хешей паролей
    const isMatch = await bcrypt.compare(password, userData.password);

    if (!isMatch) return res.status(401).send("Неверный логин или пароль");

    // Генерируем JWT-токен
    const token = jwt.sign({ id: userData.id }, process.env.JWT_SECRET_KEY, { expiresIn: '1h' });

    res.json({ token });
  } catch(err) {
    console.error(err.message);
    res.status(500).send("Ошибка авторизации");
  }
});

app.delete('/delete/:id', async (req, res) => {
  const { id } = req.params;

  try {
    await bucket.remove(id);
    res.sendStatus(204); // Пользователь успешно удалён
  } catch(err) {
    console.error(err.message);
    res.status(500).send("Ошибка удаления пользователя");
  }
});

// Запускаем сервер
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));