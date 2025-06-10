
import {createRoot} from "react-dom/client";
import {App} from "./App";

import "@fontsource/roboto";

import "./public/css/custom.css";


let container:HTMLElement|undefined = undefined;
const load = () => {
    if (!container) {
        console.log(container);
        container = document.getElementById('root') as HTMLElement;
        if(container) {
            createRoot(container).render(<App/>);
            document.removeEventListener('DOMContentLoaded', load);
        }
    }
}
document.addEventListener('DOMContentLoaded', load);
