const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const multer = require('multer');
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');
const Joi = require('joi');
const nodemailer = require('nodemailer');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const swaggerJsdoc = require('swagger-jsdoc');
const swaggerUi = require('swagger-ui-express');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'narvaez-store-secret';

// ===================
// CONFIGURACIÓN SWAGGER
// ===================
const swaggerOptions = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'API Tienda Narváez',
      version: '2.0.0',
      description: 'API RESTful completa para tienda de ropa con funcionalidades avanzadas',
      contact: {
        name: 'Tienda Narváez',
        email: 'soporte@narvaez.com'
      }
    },
    servers: [
      {
        url: `http://localhost:${PORT}`,
        description: 'Servidor de desarrollo'
      }
    ],
    components: {
      securitySchemes: {
        BearerAuth: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT'
        }
      }
    }
  },
  apis: ['./server.js']
};

const specs = swaggerJsdoc(swaggerOptions);

// ===================
// CONFIGURACIÓN CLOUDINARY
// ===================
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

const storage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: 'narvaez-store',
    allowed_formats: ['jpg', 'png', 'jpeg', 'webp'],
    transformation: [{ width: 800, height: 800, crop: 'limit' }]
  }
});

const upload = multer({ 
  storage: storage,
  limits: { fileSize: 5 * 1024 * 1024 } // 5MB
});

// ===================
// CONFIGURACIÓN EMAIL
// ===================
const transporter = nodemailer.createTransporter({
  host: process.env.SMTP_HOST,
  port: process.env.SMTP_PORT,
  secure: false,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS
  }
});

// ===================
// CONEXIÓN MONGODB
// ===================
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/narvaez-store', {
  useNewUrlParser: true,
  useUnifiedTopology: true
});

// ===================
// MODELOS MONGOOSE
// ===================

// Usuario
const usuarioSchema = new mongoose.Schema({
  nombre: { type: String, required: true, trim: true },
  email: { type: String, required: true, unique: true, lowercase: true },
  password: { type: String, required: true, minlength: 6 },
  rol: { type: String, enum: ['cliente', 'admin'], default: 'cliente' },
  telefono: { type: String },
  direccion: {
    calle: String,
    ciudad: String,
    departamento: String,
    codigoPostal: String
  },
  fechaRegistro: { type: Date, default: Date.now },
  emailVerificado: { type: Boolean, default: false },
  tokenVerificacion: String
}, { timestamps: true });

const Usuario = mongoose.model('Usuario', usuarioSchema);

// Producto
const productoSchema = new mongoose.Schema({
  nombre: { type: String, required: true, trim: true },
  descripcion: { type: String, required: true },
  precio: { type: Number, required: true, min: 0 },
  categoria: { 
    type: String, 
    required: true, 
    enum: ['camisas', 'pantalones', 'vestidos', 'zapatos', 'accesorios', 'deportiva']
  },
  genero: { 
    type: String, 
    required: true, 
    enum: ['hombre', 'mujer', 'unisex', 'niños']
  },
  tallas: [{ type: String, enum: ['XS', 'S', 'M', 'L', 'XL', 'XXL'] }],
  colores: [String],
  stock: { type: Number, required: true, min: 0 },
  imagenes: [String], // URLs de Cloudinary
  marca: String,
  activo: { type: Boolean, default: true },
  descuento: { type: Number, default: 0, min: 0, max: 100 },
  fechaCreacion: { type: Date, default: Date.now }
}, { timestamps: true });

// Índices para búsqueda
productoSchema.index({ nombre: 'text', descripcion: 'text' });
productoSchema.index({ categoria: 1, genero: 1, precio: 1 });

const Producto = mongoose.model('Producto', productoSchema);

// Carrito
const carritoSchema = new mongoose.Schema({
  usuario: { type: mongoose.Schema.Types.ObjectId, ref: 'Usuario', required: true },
  items: [{
    producto: { type: mongoose.Schema.Types.ObjectId, ref: 'Producto', required: true },
    cantidad: { type: Number, required: true, min: 1 },
    talla: String,
    color: String,
    precioUnitario: { type: Number, required: true }
  }],
  fechaActualizacion: { type: Date, default: Date.now }
}, { timestamps: true });

const Carrito = mongoose.model('Carrito', carritoSchema);

// Pedido
const pedidoSchema = new mongoose.Schema({
  usuario: { type: mongoose.Schema.Types.ObjectId, ref: 'Usuario', required: true },
  items: [{
    producto: { type: mongoose.Schema.Types.ObjectId, ref: 'Producto' },
    nombre: String,
    precio: Number,
    cantidad: Number,
    talla: String,
    color: String
  }],
  total: { type: Number, required: true },
  subtotal: { type: Number, required: true },
  impuestos: { type: Number, default: 0 },
  envio: { type: Number, default: 0 },
  descuento: { type: Number, default: 0 },
  estado: { 
    type: String, 
    enum: ['pendiente', 'confirmado', 'enviado', 'entregado', 'cancelado'],
    default: 'pendiente'
  },
  direccionEnvio: {
    nombre: String,
    calle: String,
    ciudad: String,
    departamento: String,
    codigoPostal: String,
    telefono: String
  },
  metodoPago: {
    tipo: { type: String, enum: ['tarjeta_credito', 'tarjeta_debito', 'pse', 'efectivo'] },
    stripePaymentIntentId: String,
    estado: { type: String, enum: ['pendiente', 'completado', 'fallido'], default: 'pendiente' }
  },
  numeroSeguimiento: String,
  fechaPedido: { type: Date, default: Date.now },
  fechaEnvio: Date,
  fechaEntrega: Date
}, { timestamps: true });

const Pedido = mongoose.model('Pedido', pedidoSchema);

// ===================
// ESQUEMAS DE VALIDACIÓN JOI
// ===================
const schemas = {
  registro: Joi.object({
    nombre: Joi.string().min(2).max(50).required().messages({
      'string.min': 'El nombre debe tener al menos 2 caracteres',
      'any.required': 'El nombre es requerido'
    }),
    email: Joi.string().email().required().messages({
      'string.email': 'Debe ser un email válido',
      'any.required': 'El email es requerido'
    }),
    password: Joi.string().min(6).required().messages({
      'string.min': 'La contraseña debe tener al menos 6 caracteres',
      'any.required': 'La contraseña es requerida'
    }),
    telefono: Joi.string().pattern(/^[0-9+\-\s()]+$/),
    direccion: Joi.object({
      calle: Joi.string(),
      ciudad: Joi.string(),
      departamento: Joi.string(),
      codigoPostal: Joi.string()
    })
  }),

  producto: Joi.object({
    nombre: Joi.string().min(3).max(100).required(),
    descripcion: Joi.string().min(10).max(1000).required(),
    precio: Joi.number().positive().required(),
    categoria: Joi.string().valid('camisas', 'pantalones', 'vestidos', 'zapatos', 'accesorios', 'deportiva').required(),
    genero: Joi.string().valid('hombre', 'mujer', 'unisex', 'niños').required(),
    tallas: Joi.array().items(Joi.string().valid('XS', 'S', 'M', 'L', 'XL', 'XXL')),
    colores: Joi.array().items(Joi.string()),
    stock: Joi.number().integer().min(0).required(),
    marca: Joi.string().max(50),
    descuento: Joi.number().min(0).max(100)
  }),

  carrito: Joi.object({
    productoId: Joi.string().pattern(/^[0-9a-fA-F]{24}$/).required(),
    cantidad: Joi.number().integer().min(1).max(10).required(),
    talla: Joi.string(),
    color: Joi.string()
  }),

  pedido: Joi.object({
    direccionEnvio: Joi.object({
      nombre: Joi.string().required(),
      calle: Joi.string().required(),
      ciudad: Joi.string().required(),
      departamento: Joi.string().required(),
      codigoPostal: Joi.string().required(),
      telefono: Joi.string().required()
    }).required(),
    metodoPago: Joi.string().valid('tarjeta_credito', 'tarjeta_debito', 'pse', 'efectivo').required()
  })
};

// ===================
// MIDDLEWARE
// ===================

// Seguridad
app.use(helmet());

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 100 // límite de 100 requests por ventana por IP
});
app.use('/api/', limiter);

// Rate limiting más estricto para auth
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5, // solo 5 intentos de login por IP cada 15 minutos
  message: { error: 'Demasiados intentos de login. Intenta de nuevo en 15 minutos.' }
});

app.use(cors());
app.use(express.json({ limit: '10mb' }));

// Middleware de validación
const validate = (schema) => {
  return (req, res, next) => {
    const { error } = schema.validate(req.body);
    if (error) {
      const details = error.details.map(detail => detail.message);
      return res.status(400).json({ 
        error: 'Error de validación', 
        detalles: details 
      });
    }
    next();
  };
};

// Middleware de autenticación
const authenticateToken = async (req, res, next) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      return res.status(401).json({ error: 'Token de acceso requerido' });
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    const usuario = await Usuario.findById(decoded.id);
    
    if (!usuario) {
      return res.status(401).json({ error: 'Usuario no encontrado' });
    }

    req.user = usuario;
    next();
  } catch (error) {
    return res.status(403).json({ error: 'Token inválido' });
  }
};

// Middleware para verificar rol de admin
const requireAdmin = (req, res, next) => {
  if (req.user.rol !== 'admin') {
    return res.status(403).json({ error: 'Acceso denegado. Se requieren permisos de administrador' });
  }
  next();
};

// ===================
// FUNCIONES AUXILIARES
// ===================

// Enviar email
const sendEmail = async (to, subject, html) => {
  try {
    await transporter.sendMail({
      from: process.env.FROM_EMAIL || 'noreply@narvaez.com',
      to,
      subject,
      html
    });
  } catch (error) {
    console.error('Error enviando email:', error);
  }
};

// Generar token de verificación
const generateVerificationToken = () => {
  return Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
};

// Calcular precios
const calcularPrecios = (items) => {
  const subtotal = items.reduce((sum, item) => sum + (item.precioUnitario * item.cantidad), 0);
  const impuestos = subtotal * 0.19; // IVA 19%
  const envio = subtotal > 100000 ? 0 : 8000; // Envío gratis sobre $100.000
  const total = subtotal + impuestos + envio;
  
  return { subtotal, impuestos, envio, total };
};

// ===================
// DOCUMENTACIÓN SWAGGER
// ===================
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(specs));

/**
 * @swagger
 * components:
 *   schemas:
 *     Usuario:
 *       type: object
 *       required:
 *         - nombre
 *         - email
 *         - password
 *       properties:
 *         nombre:
 *           type: string
 *           minLength: 2
 *           maxLength: 50
 *         email:
 *           type: string
 *           format: email
 *         password:
 *           type: string
 *           minLength: 6
 *         telefono:
 *           type: string
 *         direccion:
 *           type: object
 *           properties:
 *             calle:
 *               type: string
 *             ciudad:
 *               type: string
 *             departamento:
 *               type: string
 *             codigoPostal:
 *               type: string
 *     Producto:
 *       type: object
 *       required:
 *         - nombre
 *         - descripcion
 *         - precio
 *         - categoria
 *         - genero
 *         - stock
 *       properties:
 *         nombre:
 *           type: string
 *           minLength: 3
 *           maxLength: 100
 *         descripcion:
 *           type: string
 *           minLength: 10
 *           maxLength: 1000
 *         precio:
 *           type: number
 *           minimum: 0
 *         categoria:
 *           type: string
 *           enum: [camisas, pantalones, vestidos, zapatos, accesorios, deportiva]
 *         genero:
 *           type: string
 *           enum: [hombre, mujer, unisex, niños]
 *         tallas:
 *           type: array
 *           items:
 *             type: string
 *             enum: [XS, S, M, L, XL, XXL]
 *         colores:
 *           type: array
 *           items:
 *             type: string
 *         stock:
 *           type: integer
 *           minimum: 0
 *         imagenes:
 *           type: array
 *           items:
 *             type: string
 *         marca:
 *           type: string
 *         descuento:
 *           type: number
 *           minimum: 0
 *           maximum: 100
 */

// ===================
// RUTAS DE AUTENTICACIÓN
// ===================

/**
 * @swagger
 * /api/auth/registro:
 *   post:
 *     summary: Registrar nuevo usuario
 *     tags: [Autenticación]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/Usuario'
 *     responses:
 *       201:
 *         description: Usuario registrado exitosamente
 *       400:
 *         description: Error de validación
 *       409:
 *         description: Usuario ya existe
 */
app.post('/api/auth/registro', authLimiter, validate(schemas.registro), async (req, res) => {
  try {
    const { nombre, email, password, telefono, direccion } = req.body;

    // Verificar si el usuario ya existe
    const usuarioExistente = await Usuario.findOne({ email });
    if (usuarioExistente) {
      return res.status(409).json({ error: 'El usuario ya existe' });
    }

    // Encriptar contraseña
    const hashedPassword = await bcrypt.hash(password, 12);
    const tokenVerificacion = generateVerificationToken();

    // Crear nuevo usuario
    const nuevoUsuario = new Usuario({
      nombre,
      email,
      password: hashedPassword,
      telefono,
      direccion,
      tokenVerificacion
    });

    await nuevoUsuario.save();

    // Enviar email de verificación
    const verificationLink = `${req.protocol}://${req.get('host')}/api/auth/verificar-email/${tokenVerificacion}`;
    await sendEmail(
      email,
      'Verificación de cuenta - Tienda Narváez',
      `
        <h2>¡Bienvenido a Tienda Narváez!</h2>
        <p>Hola ${nombre},</p>
        <p>Gracias por registrarte. Por favor verifica tu cuenta haciendo click en el siguiente enlace:</p>
        <a href="${verificationLink}" style="background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Verificar Email</a>
        <p>Si no puedes hacer click en el botón, copia y pega este enlace en tu navegador:</p>
        <p>${verificationLink}</p>
      `
    );

    // Generar token
    const token = jwt.sign(
      { id: nuevoUsuario._id, email: nuevoUsuario.email, rol: nuevoUsuario.rol },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.status(201).json({
      mensaje: 'Usuario registrado exitosamente. Por favor verifica tu email.',
      token,
      usuario: {
        id: nuevoUsuario._id,
        nombre: nuevoUsuario.nombre,
        email: nuevoUsuario.email,
        rol: nuevoUsuario.rol,
        emailVerificado: nuevoUsuario.emailVerificado
      }
    });
  } catch (error) {
    console.error('Error en registro:', error);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

/**
 * @swagger
 * /api/auth/login:
 *   post:
 *     summary: Iniciar sesión
 *     tags: [Autenticación]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *               - password
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *               password:
 *                 type: string
 *     responses:
 *       200:
 *         description: Login exitoso
 *       401:
 *         description: Credenciales inválidas
 */
app.post('/api/auth/login', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;

    // Buscar usuario
    const usuario = await Usuario.findOne({ email });
    if (!usuario) {
      return res.status(401).json({ error: 'Credenciales inválidas' });
    }

    // Verificar contraseña
    const passwordValida = await bcrypt.compare(password, usuario.password);
    if (!passwordValida) {
      return res.status(401).json({ error: 'Credenciales inválidas' });
    }

    // Generar token
    const token = jwt.sign(
      { id: usuario._id, email: usuario.email, rol: usuario.rol },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      mensaje: 'Login exitoso',
      token,
      usuario: {
        id: usuario._id,
        nombre: usuario.nombre,
        email: usuario.email,
        rol: usuario.rol,
        emailVerificado: usuario.emailVerificado
      }
    });
  } catch (error) {
    console.error('Error en login:', error);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// Verificación de email
app.get('/api/auth/verificar-email/:token', async (req, res) => {
  try {
    const { token } = req.params;
    
    const usuario = await Usuario.findOne({ tokenVerificacion: token });
    if (!usuario) {
      return res.status(400).json({ error: 'Token de verificación inválido' });
    }

    usuario.emailVerificado = true;
    usuario.tokenVerificacion = undefined;
    await usuario.save();

    res.json({ mensaje: 'Email verificado exitosamente' });
  } catch (error) {
    console.error('Error en verificación:', error);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// ===================
// RUTAS DE PRODUCTOS
// ===================

/**
 * @swagger
 * /api/productos:
 *   get:
 *     summary: Listar productos con filtros
 *     tags: [Productos]
 *     parameters:
 *       - in: query
 *         name: categoria
 *         schema:
 *           type: string
 *         description: Filtrar por categoría
 *       - in: query
 *         name: genero
 *         schema:
 *           type: string
 *         description: Filtrar por género
 *       - in: query
 *         name: precioMin
 *         schema:
 *           type: number
 *         description: Precio mínimo
 *       - in: query
 *         name: precioMax
 *         schema:
 *           type: number
 *         description: Precio máximo
 *       - in: query
 *         name: buscar
 *         schema:
 *           type: string
 *         description: Buscar por nombre o descripción
 *       - in: query
 *         name: page
 *         schema:
 *           type: integer
 *           default: 1
 *         description: Número de página
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *           default: 20
 *         description: Productos por página
 *     responses:
 *       200:
 *         description: Lista de productos
 */
app.get('/api/productos', async (req, res) => {
  try {
    const { 
      categoria, 
      genero, 
      precioMin, 
      precioMax, 
      buscar, 
      page = 1, 
      limit = 20,
      ordenar = 'fechaCreacion'
    } = req.query;

    // Construir filtro
    let filtro = { activo: true };

    if (categoria) filtro.categoria = categoria;
    if (genero) filtro.genero = genero;
    if (precioMin || precioMax) {
      filtro.precio = {};
      if (precioMin) filtro.precio.$gte = parseFloat(precioMin);
      if (precioMax) filtro.precio.$lte = parseFloat(precioMax);
    }
    if (buscar) {
      filtro.$text = { $search: buscar };
    }

    // Configurar ordenamiento
    let sortOption = {};
    switch (ordenar) {
      case 'precio_asc':
        sortOption = { precio: 1 };
        break;
      case 'precio_desc':
        sortOption = { precio: -1 };
        break;
      case 'nombre':
        sortOption = { nombre: 1 };
        break;
      default:
        sortOption = { fechaCreacion: -1 };
    }

    // Paginación
    const skip = (parseInt(page) - 1) * parseInt(limit);

    const productos = await Producto.find(filtro)
      .sort(sortOption)
      .skip(skip)
      .limit(parseInt(limit));

    const total = await Producto.countDocuments(filtro);
    const totalPages = Math.ceil(total / parseInt(limit));

    res.json({
      productos,
      paginacion: {
        total,
        totalPages,
        currentPage: parseInt(page),
        hasNext: parseInt(page) < totalPages,
        hasPrev: parseInt(page) > 1
      }
    });
  } catch (error) {
    console.error('Error obteniendo productos:', error);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// Obtener producto por ID
app.get('/api/productos/:id', async (req, res) => {
  try {
    const producto = await Producto.findOne({ _id: req.params.id, activo: true });
    if (!producto) {
      return res.status(404).json({ error: 'Producto no encontrado' });
    }
    res.json(producto);
  } catch (error) {
    console.error('Error obteniendo producto:', error);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

/**
 * @swagger
 * /api/productos:
 *   post:
 *     summary: Crear nuevo producto (Solo Admin)
 *     tags: [Productos]
 *     security:
 *       - BearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         multipart/form-data:
 *           schema:
 *             type: object
 *             properties:
 *               nombre:
 *                 type: string
 *               descripcion:
 *                 type: string
 *               precio:
 *                 type: number
 *               categoria:
 *                 type: string
 *               genero:
 *                 type: string
 *               tallas:
 *                 type: string
 *               colores:
 *                 type: string
 *               stock:
 *                 type: integer
 *               marca:
 *                 type: string
 *               imagenes:
 *                 type: array
 *                 items:
 *                   type: string
 *                   format: binary
 *     responses:
 *       201:
 *         description: Producto creado exitosamente
 *       400:
 *         description: Error de validación
 *       403:
 *         description: Acceso denegado
 */
app.post('/api/productos', 
  authenticateToken, 
  requireAdmin, 
  upload.array('imagenes', 5),
  validate(schemas.producto),
  async (req, res) => {
    try {
      const { 
        nombre, descripcion, precio, categoria, genero, 
        tallas, colores, stock, marca, descuento 
      } = req.body;

      // Procesar imágenes subidas
      const imagenes = req.files ? req.files.map(file => file.path) : [];

      // Procesar arrays que vienen como strings
      const tallasArray = typeof tallas === 'string' ? tallas.split(',') : tallas || [];
      const coloresArray = typeof colores === 'string' ? colores.split(',') : colores || [];

      const nuevoProducto = new Producto({
        nombre,
        descripcion,
        precio: parseFloat(precio),
        categoria,
        genero,
        tallas: tallasArray,
        colores: coloresArray,
        stock: parseInt(stock),
        marca,
        descuento: descuento ? parseFloat(descuento) : 0,
        imagenes
      });

      await nuevoProducto.save();

      res.status(201).json({
        mensaje: 'Producto creado exitosamente',
        producto: nuevoProducto
      });
    } catch (error) {
      console.error('Error creando producto:', error);
      res.status(500).json({ error: 'Error interno del servidor' });
    }
  }
);

// ===================
// RUTAS DE CARRITO
// ===================

/**
 * @swagger
 * /api/carrito:
 *   post:
 *     summary: Agregar producto al carrito
 *     tags: [Carrito]
 *     security:
 *       - BearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - productoId
 *               - cantidad
 *             properties:
 *               productoId:
 *                 type: string
 *               cantidad:
 *                 type: integer
 *                 minimum: 1
 *                 maximum: 10
 *               talla:
 *                 type: string
 *               color:
 *                 type: string
 *     responses:
 *       200:
 *         description: Producto agregado al carrito
 *       400:
 *         description: Error de validación o stock insuficiente
 *       404:
 *         description: Producto no encontrado
 */
app.post('/api/carrito', authenticateToken, validate(schemas.carrito), async (req, res) => {
  try {
    const { productoId, cantidad, talla, color } = req.body;
    const userId = req.user._id;

    // Verificar que el producto existe y está activo
    const producto = await Producto.findOne({ _id: productoId, activo: true });
    if (!producto) {
      return res.status(404).json({ error: 'Producto no encontrado' });
    }

    // Verificar stock
    if (producto.stock < cantidad) {
      return res.status(400).json({ 
        error: 'Stock insuficiente', 
        disponible: producto.stock 
      });
    }

    // Buscar carrito existente o crear uno nuevo
    let carrito = await Carrito.findOne({ usuario: userId });
    if (!carrito) {
      carrito = new Carrito({ usuario: userId, items: [] });
    }

    // Buscar si ya existe el mismo producto con las mismas características
    const itemExistenteIndex = carrito.items.findIndex(
      item => 
        item.producto.toString() === productoId && 
        item.talla === talla && 
        item.color === color
    );

    const precioFinal = producto.precio * (1 - producto.descuento / 100);

    if (itemExistenteIndex > -1) {
      // Actualizar cantidad existente
      const nuevaCantidad = carrito.items[itemExistenteIndex].cantidad + cantidad;
      
      if (nuevaCantidad > producto.stock) {
        return res.status(400).json({ 
          error: 'Stock insuficiente para la cantidad total solicitada',
          disponible: producto.stock,
          enCarrito: carrito.items[itemExistenteIndex].cantidad
        });
      }
      
      carrito.items[itemExistenteIndex].cantidad = nuevaCantidad;
      carrito.items[itemExistenteIndex].precioUnitario = precioFinal;
    } else {
      // Agregar nuevo item
      carrito.items.push({
        producto: productoId,
        cantidad,
        talla,
        color,
        precioUnitario: precioFinal
      });
    }

    carrito.fechaActualizacion = new Date();
    await carrito.save();

    res.json({ 
      mensaje: 'Producto agregado al carrito exitosamente',
      carrito: await carrito.populate('items.producto')
    });
  } catch (error) {
    console.error('Error agregando al carrito:', error);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// Obtener carrito del usuario
app.get('/api/carrito', authenticateToken, async (req, res) => {
  try {
    const userId = req.user._id;
    
    const carrito = await Carrito.findOne({ usuario: userId })
      .populate('items.producto');

    if (!carrito || carrito.items.length === 0) {
      return res.json({ items: [], totales: { subtotal: 0, impuestos: 0, envio: 0, total: 0 } });
    }

    // Filtrar items de productos inactivos
    carrito.items = carrito.items.filter(item => item.producto && item.producto.activo);

    // Calcular totales
    const totales = calcularPrecios(carrito.items);

    res.json({
      items: carrito.items,
      totales,
      fechaActualizacion: carrito.fechaActualizacion
    });
  } catch (error) {
    console.error('Error obteniendo carrito:', error);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// Actualizar cantidad en carrito
app.put('/api/carrito/:itemId', authenticateToken, async (req, res) => {
  try {
    const { itemId } = req.params;
    const { cantidad } = req.body;
    const userId = req.user._id;

    if (!cantidad || cantidad < 1 || cantidad > 10) {
      return res.status(400).json({ error: 'La cantidad debe estar entre 1 y 10' });
    }

    const carrito = await Carrito.findOne({ usuario: userId });
    if (!carrito) {
      return res.status(404).json({ error: 'Carrito no encontrado' });
    }

    const itemIndex = carrito.items.findIndex(item => item._id.toString() === itemId);
    if (itemIndex === -1) {
      return res.status(404).json({ error: 'Item no encontrado en el carrito' });
    }

    // Verificar stock del producto
    const producto = await Producto.findById(carrito.items[itemIndex].producto);
    if (producto.stock < cantidad) {
      return res.status(400).json({ 
        error: 'Stock insuficiente', 
        disponible: producto.stock 
      });
    }

    carrito.items[itemIndex].cantidad = cantidad;
    carrito.fechaActualizacion = new Date();
    await carrito.save();

    res.json({ mensaje: 'Cantidad actualizada exitosamente' });
  } catch (error) {
    console.error('Error actualizando carrito:', error);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// Eliminar item del carrito
app.delete('/api/carrito/:itemId', authenticateToken, async (req, res) => {
  try {
    const { itemId } = req.params;
    const userId = req.user._id;

    const carrito = await Carrito.findOne({ usuario: userId });
    if (!carrito) {
      return res.status(404).json({ error: 'Carrito no encontrado' });
    }

    carrito.items = carrito.items.filter(item => item._id.toString() !== itemId);
    carrito.fechaActualizacion = new Date();
    await carrito.save();

    res.json({ mensaje: 'Item eliminado del carrito exitosamente' });
  } catch (error) {
    console.error('Error eliminando del carrito:', error);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// ===================
// RUTAS DE PAGOS (STRIPE)
// ===================

/**
 * @swagger
 * /api/pagos/create-payment-intent:
 *   post:
 *     summary: Crear intención de pago con Stripe
 *     tags: [Pagos]
 *     security:
 *       - BearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - monto
 *               - moneda
 *             properties:
 *               monto:
 *                 type: number
 *                 description: Monto en centavos
 *               moneda:
 *                 type: string
 *                 default: cop
 *               descripcion:
 *                 type: string
 *     responses:
 *       200:
 *         description: Payment Intent creado exitosamente
 */
app.post('/api/pagos/create-payment-intent', authenticateToken, async (req, res) => {
  try {
    const { monto, moneda = 'cop', descripcion } = req.body;

    if (!monto || monto < 50) { // Mínimo $0.50
      return res.status(400).json({ error: 'Monto mínimo requerido' });
    }

    const paymentIntent = await stripe.paymentIntents.create({
      amount: Math.round(monto * 100), // Stripe usa centavos
      currency: moneda,
      description: descripcion || 'Compra en Tienda Narváez',
      metadata: {
        usuarioId: req.user._id.toString()
      }
    });

    res.json({
      clientSecret: paymentIntent.client_secret,
      paymentIntentId: paymentIntent.id
    });
  } catch (error) {
    console.error('Error creando Payment Intent:', error);
    res.status(500).json({ error: 'Error procesando el pago' });
  }
});

// Confirmar pago
app.post('/api/pagos/confirmar/:paymentIntentId', authenticateToken, async (req, res) => {
  try {
    const { paymentIntentId } = req.params;
    
    const paymentIntent = await stripe.paymentIntents.retrieve(paymentIntentId);
    
    if (paymentIntent.status === 'succeeded') {
      res.json({ 
        mensaje: 'Pago confirmado exitosamente',
        estado: 'completado',
        paymentIntentId 
      });
    } else {
      res.status(400).json({ 
        error: 'El pago no ha sido completado',
        estado: paymentIntent.status 
      });
    }
  } catch (error) {
    console.error('Error confirmando pago:', error);
    res.status(500).json({ error: 'Error verificando el pago' });
  }
});

// ===================
// RUTAS DE PEDIDOS
// ===================

/**
 * @swagger
 * /api/pedidos:
 *   post:
 *     summary: Crear nuevo pedido
 *     tags: [Pedidos]
 *     security:
 *       - BearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - direccionEnvio
 *               - metodoPago
 *             properties:
 *               direccionEnvio:
 *                 type: object
 *                 required:
 *                   - nombre
 *                   - calle
 *                   - ciudad
 *                   - departamento
 *                   - codigoPostal
 *                   - telefono
 *                 properties:
 *                   nombre:
 *                     type: string
 *                   calle:
 *                     type: string
 *                   ciudad:
 *                     type: string
 *                   departamento:
 *                     type: string
 *                   codigoPostal:
 *                     type: string
 *                   telefono:
 *                     type: string
 *               metodoPago:
 *                 type: string
 *                 enum: [tarjeta_credito, tarjeta_debito, pse, efectivo]
 *               paymentIntentId:
 *                 type: string
 *                 description: ID del Payment Intent de Stripe (requerido para pagos con tarjeta)
 *     responses:
 *       201:
 *         description: Pedido creado exitosamente
 *       400:
 *         description: Error de validación o carrito vacío
 */
app.post('/api/pedidos', authenticateToken, validate(schemas.pedido), async (req, res) => {
  try {
    const { direccionEnvio, metodoPago, paymentIntentId } = req.body;
    const userId = req.user._id;

    // Obtener carrito del usuario
    const carrito = await Carrito.findOne({ usuario: userId })
      .populate('items.producto');

    if (!carrito || carrito.items.length === 0) {
      return res.status(400).json({ error: 'El carrito está vacío' });
    }

    // Verificar stock de todos los productos
    for (const item of carrito.items) {
      if (!item.producto.activo) {
        return res.status(400).json({ 
          error: `El producto ${item.producto.nombre} ya no está disponible` 
        });
      }
      if (item.producto.stock < item.cantidad) {
        return res.status(400).json({ 
          error: `Stock insuficiente para ${item.producto.nombre}`,
          disponible: item.producto.stock,
          solicitado: item.cantidad
        });
      }
    }

    // Verificar pago si es con tarjeta
    if (['tarjeta_credito', 'tarjeta_debito'].includes(metodoPago)) {
      if (!paymentIntentId) {
        return res.status(400).json({ error: 'Payment Intent ID requerido para pagos con tarjeta' });
      }

      const paymentIntent = await stripe.paymentIntents.retrieve(paymentIntentId);
      if (paymentIntent.status !== 'succeeded') {
        return res.status(400).json({ error: 'El pago no ha sido completado' });
      }
    }

    // Calcular totales
    const totales = calcularPrecios(carrito.items);

    // Crear pedido
    const nuevoPedido = new Pedido({
      usuario: userId,
      items: carrito.items.map(item => ({
        producto: item.producto._id,
        nombre: item.producto.nombre,
        precio: item.precioUnitario,
        cantidad: item.cantidad,
        talla: item.talla,
        color: item.color
      })),
      subtotal: totales.subtotal,
      impuestos: totales.impuestos,
      envio: totales.envio,
      total: totales.total,
      direccionEnvio,
      metodoPago: {
        tipo: metodoPago,
        stripePaymentIntentId: paymentIntentId,
        estado: paymentIntentId ? 'completado' : 'pendiente'
      }
    });

    await nuevoPedido.save();

    // Actualizar stock de productos
    for (const item of carrito.items) {
      await Producto.findByIdAndUpdate(
        item.producto._id,
        { $inc: { stock: -item.cantidad } }
      );
    }

    // Limpiar carrito
    await Carrito.findOneAndDelete({ usuario: userId });

    // Enviar email de confirmación
    await sendEmail(
      req.user.email,
      `Pedido Confirmado #${nuevoPedido._id}`,
      `
        <h2>¡Pedido Confirmado!</h2>
        <p>Hola ${req.user.nombre},</p>
        <p>Tu pedido #${nuevoPedido._id} ha sido confirmado exitosamente.</p>
        <h3>Detalles del pedido:</h3>
        <ul>
          ${nuevoPedido.items.map(item => 
            `<li>${item.nombre} - Cantidad: ${item.cantidad} - ${item.precio.toLocaleString()}</li>`
          ).join('')}
        </ul>
        <p><strong>Total: ${nuevoPedido.total.toLocaleString()}</strong></p>
        <p>Será enviado a:</p>
        <p>${direccionEnvio.nombre}<br>
        ${direccionEnvio.calle}<br>
        ${direccionEnvio.ciudad}, ${direccionEnvio.departamento}<br>
        ${direccionEnvio.codigoPostal}</p>
        <p>Te notificaremos cuando tu pedido sea enviado.</p>
      `
    );

    res.status(201).json({
      mensaje: 'Pedido creado exitosamente',
      pedido: nuevoPedido
    });
  } catch (error) {
    console.error('Error creando pedido:', error);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// Obtener pedidos del usuario
app.get('/api/pedidos', authenticateToken, async (req, res) => {
  try {
    const userId = req.user._id;
    const { page = 1, limit = 10 } = req.query;

    const skip = (parseInt(page) - 1) * parseInt(limit);

    const pedidos = await Pedido.find({ usuario: userId })
      .sort({ fechaPedido: -1 })
      .skip(skip)
      .limit(parseInt(limit))
      .populate('items.producto', 'nombre imagenes');

    const total = await Pedido.countDocuments({ usuario: userId });

    res.json({
      pedidos,
      paginacion: {
        total,
        totalPages: Math.ceil(total / parseInt(limit)),
        currentPage: parseInt(page)
      }
    });
  } catch (error) {
    console.error('Error obteniendo pedidos:', error);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// Obtener pedido específico
app.get('/api/pedidos/:id', authenticateToken, async (req, res) => {
  try {
    const pedido = await Pedido.findOne({ 
      _id: req.params.id, 
      usuario: req.user._id 
    }).populate('items.producto', 'nombre imagenes');

    if (!pedido) {
      return res.status(404).json({ error: 'Pedido no encontrado' });
    }

    res.json(pedido);
  } catch (error) {
    console.error('Error obteniendo pedido:', error);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// ===================
// RUTAS DE ADMINISTRACIÓN
// ===================

// Obtener todos los pedidos (admin)
app.get('/api/admin/pedidos', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { 
      estado, 
      fechaInicio, 
      fechaFin, 
      page = 1, 
      limit = 20 
    } = req.query;

    let filtro = {};
    if (estado) filtro.estado = estado;
    if (fechaInicio || fechaFin) {
      filtro.fechaPedido = {};
      if (fechaInicio) filtro.fechaPedido.$gte = new Date(fechaInicio);
      if (fechaFin) filtro.fechaPedido.$lte = new Date(fechaFin);
    }

    const skip = (parseInt(page) - 1) * parseInt(limit);

    const pedidos = await Pedido.find(filtro)
      .populate('usuario', 'nombre email')
      .sort({ fechaPedido: -1 })
      .skip(skip)
      .limit(parseInt(limit));

    const total = await Pedido.countDocuments(filtro);

    res.json({
      pedidos,
      paginacion: {
        total,
        totalPages: Math.ceil(total / parseInt(limit)),
        currentPage: parseInt(page)
      }
    });
  } catch (error) {
    console.error('Error obteniendo pedidos admin:', error);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// Actualizar estado del pedido (admin)
app.put('/api/admin/pedidos/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { estado, numeroSeguimiento } = req.body;
    
    if (!['pendiente', 'confirmado', 'enviado', 'entregado', 'cancelado'].includes(estado)) {
      return res.status(400).json({ error: 'Estado inválido' });
    }

    const actualizacion = { estado };
    
    if (estado === 'enviado') {
      actualizacion.fechaEnvio = new Date();
      if (numeroSeguimiento) {
        actualizacion.numeroSeguimiento = numeroSeguimiento;
      }
    } else if (estado === 'entregado') {
      actualizacion.fechaEntrega = new Date();
    }

    const pedido = await Pedido.findByIdAndUpdate(
      req.params.id,
      actualizacion,
      { new: true }
    ).populate('usuario', 'nombre email');

    if (!pedido) {
      return res.status(404).json({ error: 'Pedido no encontrado' });
    }

    // Enviar email de notificación
    let asunto = '';
    let mensaje = '';
    
    switch (estado) {
      case 'confirmado':
        asunto = `Pedido Confirmado #${pedido._id}`;
        mensaje = 'Tu pedido ha sido confirmado y está siendo procesado.';
        break;
      case 'enviado':
        asunto = `Pedido Enviado #${pedido._id}`;
        mensaje = `Tu pedido ha sido enviado${numeroSeguimiento ? ` con número de seguimiento: ${numeroSeguimiento}` : ''}.`;
        break;
      case 'entregado':
        asunto = `Pedido Entregado #${pedido._id}`;
        mensaje = '¡Tu pedido ha sido entregado exitosamente! Gracias por tu compra.';
        break;
      case 'cancelado':
        asunto = `Pedido Cancelado #${pedido._id}`;
        mensaje = 'Lamentamos informarte que tu pedido ha sido cancelado. Te contactaremos pronto.';
        break;
    }

    if (asunto && mensaje) {
      await sendEmail(
        pedido.usuario.email,
        asunto,
        `
          <h2>Actualización de Pedido</h2>
          <p>Hola ${pedido.usuario.nombre},</p>
          <p>${mensaje}</p>
          <p>Número de pedido: #${pedido._id}</p>
          ${numeroSeguimiento ? `<p>Número de seguimiento: ${numeroSeguimiento}</p>` : ''}
        `
      );
    }

    res.json({
      mensaje: 'Estado del pedido actualizado exitosamente',
      pedido
    });
  } catch (error) {
    console.error('Error actualizando pedido:', error);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// Dashboard admin - estadísticas
app.get('/api/admin/dashboard', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const hoy = new Date();
    const inicioMes = new Date(hoy.getFullYear(), hoy.getMonth(), 1);
    const inicioAno = new Date(hoy.getFullYear(), 0, 1);

    const [
      totalUsuarios,
      totalProductos,
      pedidosHoy,
      pedidosMes,
      ventasAno,
      productosPopulares
    ] = await Promise.all([
      Usuario.countDocuments({ rol: 'cliente' }),
      Producto.countDocuments({ activo: true }),
      Pedido.countDocuments({ 
        fechaPedido: { $gte: new Date(hoy.setHours(0, 0, 0, 0)) }
      }),
      Pedido.countDocuments({ fechaPedido: { $gte: inicioMes } }),
      Pedido.aggregate([
        { $match: { fechaPedido: { $gte: inicioAno }, estado: { $ne: 'cancelado' } } },
        { $group: { _id: null, total: { $sum: '$total' } } }
      ]),
      Pedido.aggregate([
        { $match: { fechaPedido: { $gte: inicioMes } } },
        { $unwind: '$items' },
        { $group: {
          _id: '$items.producto',
          nombre: { $first: '$items.nombre' },
          totalVendido: { $sum: '$items.cantidad' }
        }},
        { $sort: { totalVendido: -1 } },
        { $limit: 5 }
      ])
    ]);

    res.json({
      resumen: {
        totalUsuarios,
        totalProductos,
        pedidosHoy,
        pedidosMes,
        ventasAno: ventasAno[0]?.total || 0
      },
      productosPopulares
    });
  } catch (error) {
    console.error('Error en dashboard:', error);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// ===================
// RUTAS DE USUARIO
// ===================

// Obtener perfil del usuario
app.get('/api/usuario/perfil', authenticateToken, async (req, res) => {
  try {
    const usuario = await Usuario.findById(req.user._id).select('-password');
    res.json(usuario);
  } catch (error) {
    console.error('Error obteniendo perfil:', error);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// Actualizar perfil del usuario
app.put('/api/usuario/perfil', authenticateToken, async (req, res) => {
  try {
    const { nombre, telefono, direccion } = req.body;
    
    const usuario = await Usuario.findByIdAndUpdate(
      req.user._id,
      { nombre, telefono, direccion },
      { new: true, runValidators: true }
    ).select('-password');

    res.json({
      mensaje: 'Perfil actualizado exitosamente',
      usuario
    });
  } catch (error) {
    console.error('Error actualizando perfil:', error);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// ===================
// INFORMACIÓN GENERAL
// ===================

/**
 * @swagger
 * /api:
 *   get:
 *     summary: Información general de la API
 *     tags: [General]
 *     responses:
 *       200:
 *         description: Información de la API
 */
app.get('/api', (req, res) => {
  res.json({
    nombre: 'API Tienda de Ropa Narváez - Versión Avanzada',
    version: '2.0.0',
    descripcion: 'API RESTful completa con funcionalidades avanzadas',
    caracteristicas: [
      'Base de datos MongoDB',
      'Validaciones con Joi',
      'Subida de imágenes con Cloudinary',
      'Pagos con Stripe',
      'Envío de emails',
      'Documentación con Swagger',
      'Seguridad con Helmet',
      'Rate limiting',
      'Paginación',
      'Filtros avanzados'
    ],
    documentacion: '/api-docs',
    endpoints: {
      auth: [
        'POST /api/auth/registro',
        'POST /api/auth/login',
        'GET /api/auth/verificar-email/:token'
      ],
      productos: [
        'GET /api/productos',
        'GET /api/productos/:id',
        'POST /api/productos (admin)',
        'PUT /api/productos/:id (admin)',
        'DELETE /api/productos/:id (admin)'
      ],
      carrito: [
        'GET /api/carrito',
        'POST /api/carrito',
        'PUT /api/carrito/:itemId',
        'DELETE /api/carrito/:itemId'
      ],
      pagos: [
        'POST /api/pagos/create-payment-intent',
        'POST /api/pagos/confirmar/:paymentIntentId'
      ],
      pedidos: [
        'GET /api/pedidos',
        'GET /api/pedidos/:id',
        'POST /api/pedidos'
      ],
      admin: [
        'GET /api/admin/pedidos',
        'PUT /api/admin/pedidos/:id',
        'GET /api/admin/dashboard'
      ],
      usuario: [
        'GET /api/usuario/perfil',
        'PUT /api/usuario/perfil'
      ]
    }
  });
});

// Manejo de rutas no encontradas
app.use('*', (req, res) => {
  res.status(404).json({ 
    error: 'Endpoint no encontrado',
    sugerencia: 'Visita /api para ver los endpoints disponibles o /api-docs para la documentación completa'
  });
});

// Manejo de errores global
app.use((err, req, res, next) => {
  console.error(err.stack);
  
  // Error de validación de Mongoose
  if (err.name === 'ValidationError') {
    const errors = Object.values(err.errors).map(e => e.message);
    return res.status(400).json({ error: 'Error de validación', detalles: errors });
  }
  
  // Error de duplicado en MongoDB
  if (err.code === 11000) {
    return res.status(409).json({ error: 'Recurso ya existe' });
  }
  
  // Error de JWT
  if (err.name === 'JsonWebTokenError') {
    return res.status(401).json({ error: 'Token inválido' });
  }
  
  res.status(500).json({ error: 'Error interno del servidor' });
});

// Iniciar servidor
app.listen(PORT, () => {
  console.log(`🚀 API Tienda Narváez v2.0 ejecutándose en http://localhost:${PORT}`);
  console.log(`📚 Documentación Swagger disponible en http://localhost:${PORT}/api-docs`);
  console.log(`🔧 Endpoints disponibles en http://localhost:${PORT}/api`);
  console.log(`📧 Configuración de email: ${process.env.SMTP_HOST ? '✅ Configurado' : '❌ Sin configurar'}`);
  console.log(`💳 Stripe
: ${process.env.STRIPE_SECRET_KEY ? '✅ Configurado' : '❌ Sin configurar'}`);