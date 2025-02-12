import { Request, Response, NextFunction } from 'express';
import logger from '../utils/logger';

export const errorHandler = (
  err: any, //TODO
  req: Request,
  res: Response,
  next: NextFunction
) => {
  logger.error(`${req.method} ${req.url} - ${err}`);

  res.status(err.status || 500).json({
    message: err.message || 'Internal Server Error',
  });
};
