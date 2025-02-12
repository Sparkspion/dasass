import { Request } from 'express';
import multer from 'multer';
import path from 'path';
import { CloudinaryStorage } from 'multer-storage-cloudinary';
import cloudinary from '../config/cloudinary';

//  Define storage for uploaded file
const storageDS = multer.diskStorage({
  destination: (_req, _file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (_req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1e9);
    cb(null, uniqueSuffix + path.extname(file.originalname));
  },
});

// Filter images
const imgFilter = (
  req: Request,
  file: Express.Multer.File,
  callback: any //TODO
) => {
  if (file.mimetype.startsWith('image/')) {
    callback(null, true);
  } else {
    callback(new Error('Only image files are allowed'), false);
  }
};

// Configure Cloudinary Storage for Multer
const storage = new CloudinaryStorage({ cloudinary });

export const upload = multer({ storage, fileFilter: imgFilter });

// export const uploadDisk = multer({ storage: storageDS, fileFilter: imgFilter });
