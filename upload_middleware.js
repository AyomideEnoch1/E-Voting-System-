const multer = require('multer');
const path   = require('path');
const fs     = require('fs');

const BASE_UPLOAD_DIR = path.join(__dirname, 'uploads');
['photos','manifestos','documents'].forEach(dir => {
  const full = path.join(BASE_UPLOAD_DIR, dir);
  if (!fs.existsSync(full)) fs.mkdirSync(full, { recursive: true });
});

const photoStorage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, path.join(BASE_UPLOAD_DIR, 'photos')),
  filename:    (req, file, cb) => cb(null, `photo-${req.params.id||'new'}-${Date.now()}${path.extname(file.originalname).toLowerCase()}`)
});
const manifestoStorage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, path.join(BASE_UPLOAD_DIR, 'manifestos')),
  filename:    (req, file, cb) => cb(null, `manifesto-${req.params.id||'new'}-${Date.now()}${path.extname(file.originalname).toLowerCase()}`)
});
const documentStorage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, path.join(BASE_UPLOAD_DIR, 'documents')),
  filename:    (req, file, cb) => {
    const safe = file.originalname.replace(/[^a-zA-Z0-9._-]/g, '_');
    cb(null, `doc-${req.params.id||'new'}-${Date.now()}-${safe}`);
  }
});

// FIX: validate both extension AND mimetype — not just extension
const PHOTO_EXTS  = ['.jpg','.jpeg','.png','.webp'];
const PHOTO_MIMES = ['image/jpeg','image/png','image/webp'];
const DOC_EXTS    = ['.pdf','.doc','.docx'];
const DOC_MIMES   = ['application/pdf','application/msword','application/vnd.openxmlformats-officedocument.wordprocessingml.document'];

const photoFilter = (req, file, cb) => {
  const ext = path.extname(file.originalname).toLowerCase();
  PHOTO_EXTS.includes(ext) && PHOTO_MIMES.includes(file.mimetype) ? cb(null, true) : cb(new Error('Only JPG, PNG and WEBP allowed'));
};
const pdfFilter = (req, file, cb) => {
  path.extname(file.originalname).toLowerCase() === '.pdf' && file.mimetype === 'application/pdf' ? cb(null, true) : cb(new Error('Only PDF allowed'));
};
const docFilter = (req, file, cb) => {
  const ext = path.extname(file.originalname).toLowerCase();
  DOC_EXTS.includes(ext) && DOC_MIMES.includes(file.mimetype) ? cb(null, true) : cb(new Error('Only PDF, DOC, DOCX allowed'));
};

const uploadPhoto     = multer({ storage: photoStorage,     fileFilter: photoFilter, limits: { fileSize: 5*1024*1024  } });
const uploadManifesto = multer({ storage: manifestoStorage, fileFilter: pdfFilter,   limits: { fileSize: 10*1024*1024 } });
const uploadDocuments = multer({ storage: documentStorage,  fileFilter: docFilter,   limits: { fileSize: 10*1024*1024 } });

const uploadCandidateFiles = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => {
      const sub = file.fieldname==='photo' ? 'photos' : file.fieldname==='manifesto_doc' ? 'manifestos' : 'documents';
      cb(null, path.join(BASE_UPLOAD_DIR, sub));
    },
    filename: (req, file, cb) => {
      const safe = file.originalname.replace(/[^a-zA-Z0-9._-]/g,'_');
      cb(null, `${file.fieldname}-${req.params.id||'new'}-${Date.now()}-${safe}`);
    }
  }),
  fileFilter: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    if (file.fieldname==='photo') return PHOTO_EXTS.includes(ext)&&PHOTO_MIMES.includes(file.mimetype) ? cb(null,true) : cb(new Error('Photo must be JPG/PNG/WEBP'));
    if (file.fieldname==='manifesto_doc') return ext==='.pdf'&&file.mimetype==='application/pdf' ? cb(null,true) : cb(new Error('Manifesto must be PDF'));
    if (file.fieldname==='extra_docs') return DOC_EXTS.includes(ext)&&DOC_MIMES.includes(file.mimetype) ? cb(null,true) : cb(new Error('Docs must be PDF/DOC/DOCX'));
    cb(new Error('Unknown field'));
  },
  limits: { fileSize: 10*1024*1024 }
}).fields([{ name:'photo', maxCount:1 }, { name:'manifesto_doc', maxCount:1 }, { name:'extra_docs', maxCount:3 }]);

function handleUpload(uploadFn) {
  return (req, res, next) => {
    uploadFn(req, res, err => {
      if (err instanceof multer.MulterError) {
        if (err.code==='LIMIT_FILE_SIZE')  return res.status(400).json({ error: 'File too large' });
        if (err.code==='LIMIT_FILE_COUNT') return res.status(400).json({ error: 'Too many files' });
        return res.status(400).json({ error: err.message });
      }
      if (err) return res.status(400).json({ error: err.message });
      next();
    });
  };
}

module.exports = {
  uploadPhoto:          handleUpload(uploadPhoto.single('photo')),
  uploadManifesto:      handleUpload(uploadManifesto.single('manifesto_doc')),
  uploadDocuments:      handleUpload(uploadDocuments.array('extra_docs', 3)),
  uploadCandidateFiles: handleUpload(uploadCandidateFiles),
  BASE_UPLOAD_DIR
};
