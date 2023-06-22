import express from 'express';
import 'express-async-errors';
import cors from 'cors';
import morgan from 'morgan';
import helmet from 'helmet';
import dotenv from 'dotenv';
import cookieParser from 'cookie-parser';

import { csrfCheck } from './middleware/csrf.js';
import rateLimit from './middleware/rate-limiter.js';

import { initSocket } from './connection/socket.js';
import { sequelize } from './db/databaseSequel.js';

import authRouter from './router/auth.js';

dotenv.config();

const app = express();

app.use(express.json());
app.use(cookieParser());
app.use(helmet());
app.use(
  cors({
    origin: 'http://localhost:3000',
    credentials: true, //allow the Access-Control-Allow-Credentials
  })
);
app.use(morgan('tiny'));

app.use(rateLimit);

//커스텀 미들웨어
app.use(csrfCheck);

app.use('/auth', authRouter);

app.use((req, res, next) => {
  res.sendStatus(404);
});

app.use((error, req, res, next) => {
  console.error(error);
  res.sendStatus(500);
});

//3. sequelize 사용시 db connection
sequelize.sync().then(client => {
  console.log(`Server is Started!!! ${new Date()}`);
  const server = app.listen(process.env.SERVER_PORT);
  //소켓사용을 위한것
  initSocket(server);
});
