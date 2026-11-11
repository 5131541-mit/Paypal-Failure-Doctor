import React from 'react';
import { createRoot } from 'react-dom/client';
import './styles.css';
import './modules.css';
import './responsive.css';
import './webhooks.css';
import './suite.css';
import App from './App.jsx';

createRoot(document.getElementById('root')).render(<React.StrictMode><App /></React.StrictMode>);
