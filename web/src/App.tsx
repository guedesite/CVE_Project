import {createTheme, NoSsr,  ThemeProvider} from "@mui/material";

import CssBaseline from '@mui/material/CssBaseline';


import {Toaster} from "react-hot-toast";
import { BrowserRouter, Route, Routes } from "react-router-dom";
import {HomePage} from "./pages/HomePage";


export const App = () => {

    const theme = createTheme({
        colorSchemes: {
            dark: false,
        },
        palette: {
            // mode: hasValue("theme") ? getValue("theme") as PaletteMode : "dark",
        },
    });


    return (
        <NoSsr>
            <ThemeProvider theme={theme}>
                <CssBaseline />
                <Toaster
                    position="top-center"
                    reverseOrder={false}
                />
                <BrowserRouter>
                    <Routes>
                        <Route path={"/"} element={<HomePage/>} />
                    </Routes>
                </BrowserRouter>

            </ThemeProvider>
        </NoSsr>
    )
};

export const DEBUG = true;