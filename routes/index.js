const routerx = require('express-promise-router');
const usuarioRouter = require('./usuario');
const articuloRouter = require('./articulo');
const categoriaRouter = require('./categoria');



const router = routerx();

router.use('/usuario', usuarioRouter);
router.use('/articulo', articuloRouter);
router.use('/categoria', categoriaRouter);

module.exports = router;