require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3001;

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
  .then(() => console.log('MongoDB connected'))
  .catch((err) => console.error('MongoDB connection error:', err));

// Middleware
app.use(express.json());
app.use(cors({
  origin: 'http://localhost:5173', // React frontend URL
  credentials: true,
}));

// User Schema & Model
const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});
const User = mongoose.model('User', UserSchema);

// Task Schema & Model
const TaskSchema = new mongoose.Schema({
  title: { type: String, required: true },
  status: { type: String, required: true },
  completionDate: { type: Date, required: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
});
const Task = mongoose.model('Task', TaskSchema);

// Middleware: Authenticate JWT
const authenticateJWT = (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  if (!token) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

// Register Route
app.post('/register', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Please provide both username and password' });
  }

  try {
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(400).json({ error: 'Username already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ username, password: hashedPassword });
    await newUser.save();

    res.status(201).json({ message: 'Registration successful!' });
  } catch (err) {
    console.error('Error during registration:', err);
    res.status(500).json({ error: 'An error occurred during registration' });
  }
});

// Login Route
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Please provide both username and password' });
  }

  try {
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(400).json({ error: 'Invalid username or password' });
    }

    const isPasswordCorrect = await bcrypt.compare(password, user.password);
    if (!isPasswordCorrect) {
      return res.status(400).json({ error: 'Invalid username or password' });
    }

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    return res.json({ token });
  } catch (err) {
    console.error('Error during login:', err); // Log the error for debugging
    return res.status(500).json({ error: 'An error occurred during login' });
  }
});

// Add Task Route (POST)
app.post('/tasks', authenticateJWT, async (req, res) => {
  const { title, status, completionDate } = req.body;

  if (!title || !status || !completionDate) {
    return res.status(400).json({ error: 'Please provide all fields' });
  }

  try {
    const newTask = new Task({
      title,
      status,
      completionDate,
      userId: req.user.userId, 
    });

    await newTask.save();
    res.status(201).json({ message: 'Task added successfully', task: newTask });
  } catch (err) {
    console.error('Error adding task:', err);
    res.status(500).json({ error: 'An error occurred while adding the task' });
  }
});


app.get('/tasks', authenticateJWT, async (req, res) => {
  try {
    
    const tasks = await Task.find({ userId: req.user.userId }); 
    res.json({ tasks });
  } catch (err) {
    console.error('Error fetching tasks:', err);
    res.status(500).json({ error: 'Failed to fetch tasks' });
  }
});


app.delete('/tasks/:id', authenticateJWT, async (req, res) => {
  const { id } = req.params;

  try {
   
    const task = await Task.findOne({ _id: id, userId: req.user.userId });
    if (!task) {
      return res.status(404).json({ error: 'Task not found or not authorized to delete it' });
    }

   
    await Task.deleteOne({ _id: id });
    res.status(200).json({ message: 'Task deleted successfully' });
  } catch (err) {
    console.error('Error deleting task:', err);
    res.status(500).json({ error: 'An error occurred while deleting the task' });
  }
});


app.put('/tasks/:id', authenticateJWT, async (req, res) => {
  const { id } = req.params;
  const { title, status, completionDate } = req.body;

  if (!title || !status || !completionDate) {
    return res.status(400).json({ error: 'Please provide all fields' });
  }

  try {
 
    const task = await Task.findOne({ _id: id, userId: req.user.userId });
    if (!task) {
      return res.status(404).json({ error: 'Task not found or not authorized to update it' });
    }

   
    task.title = title;
    task.status = status;
    task.completionDate = completionDate;

    await task.save();
    res.status(200).json({ message: 'Task updated successfully', task });
  } catch (err) {
    console.error('Error updating task:', err);
    res.status(500).json({ error: 'An error occurred while updating the task' });
  }
});


app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
