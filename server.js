import express from 'express';
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

// Connection to mongodb
mongoose.connect(process.env.DB_URL, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
});

// Modele User
const User = mongoose.model('User', new mongoose.Schema({
    username: { type: String, unique: true, required: true },
    password: { type: String, required: true },
}));

// POST /register
app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    try {
        const existingUser = await User.findOne({ username });
        if (existingUser) {
            return res.status(400).json({ message: 'Cet utilisateur existe déjà.' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({ username, password: hashedPassword });
        await user.save();

        res.status(201).json({ message: 'Inscription réussie.' });
    } catch (error) {
        res.status(500).json({ error: 'Erreur lors de l\'inscription.' });
    }
});

// POST /login
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user) {
        return res.status(400).json({ error: 'Utilisateur non trouvé' });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
        return res.status(400).json({ error: 'Mot de passe incorrect' });
    }

    const token = jwt.sign({ id: user._id, username: user.username }, 'secret_key', { expiresIn: '1h' });
    res.json({ message: 'Connexion réussie', token });
});

// GET /users
app.get('/users', async (req, res) => {
    try {
        const users = await User.find({}, 'username');
        res.json(users);
    } catch (error) {
        res.status(500).json({ error: 'Erreur lors de la récupération des utilisateurs.' });
    }
});

// PUT /users/:id
app.put('/users/:id', async (req, res) => {
    try {
        const userId = req.params.id;
        const { username } = req.body;
        const updatedUser = await User.findByIdAndUpdate(userId, { username }, { new: true });

        res.json(updatedUser);
    } catch (error) {
        res.status(500).json({ error: 'Erreur lors de la mise à jour de l\'utilisateur.' });
    }
});

// PUT /users/:id/password
app.put('/users/:id/password', async (req, res) => {
    const { newPassword } = req.body;
    const userId = req.params.id;

    try {
        if (!newPassword) {
            return res.status(400).json({ error: 'Le mot de passe est requis.' });
        }
        const hashedPassword = await bcrypt.hash(newPassword, 10);

        const updatedUser = await User.findByIdAndUpdate(userId, { password: hashedPassword }, { new: true });

        res.json({ message: 'Mot de passe mis à jour avec succès.' });
    } catch (error) {
        res.status(500).json({ error: 'Erreur lors de la mise à jour du mot de passe.' });
    }
});

// test server
app.listen(3000, () => {
    console.log('Backend démarré sur le port 3000');
});