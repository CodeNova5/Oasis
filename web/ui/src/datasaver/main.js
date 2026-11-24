import { render } from 'preact';
import { html } from 'htm/preact';
import { App } from './App.js';
import './styles.css';

render(html`<${App} />`, document.getElementById('app'));
