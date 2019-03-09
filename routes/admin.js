const express = require('express');
const { body } = require('express-validator/check');

const adminController = require('../controllers/admin');
const isAuth = require('../middleware/is-auth');

const router = express.Router();

// /admin/add-product => GET
router.get('/add-product', isAuth, adminController.getAddProduct);

// /admin/products => GET
router.get('/products', isAuth, adminController.getProducts);

// /admin/add-product => POST
router.post('/add-product', [
    body('title', 'Title should be atlease 3 Characters')
        .isString()
        .isLength({ min: 3 })
        .trim(),
    body('price', 'Price should be only float').isFloat(),
    body('description', 'Description should be atleast 5 and max 400 characters')
        .isString()
        .isLength({ min: 5, max: 400 })
        .trim()
], isAuth, adminController.postAddProduct);

router.get('/edit-product/:productId', isAuth, adminController.getEditProduct);

router.post('/edit-product', [
    body('title', 'Title should be atlease 3 Characters')
        .isString()
        .isLength({ min: 3 })
        .trim(),
    body('price', 'Price should be only float').isFloat(),
    body('description', 'Description should be atleast 5 and max 400 characters')
        .isString()
        .isLength({ min: 5, max: 400 })
        .trim()
], isAuth, adminController.postEditProduct);

router.delete('/product/:productId', isAuth, adminController.deleteProduct);

module.exports = router;
