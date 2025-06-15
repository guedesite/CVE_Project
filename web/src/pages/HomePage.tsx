import {
    Box,
    Button,
    Chip,
    CircularProgress,
    Divider,
    Fab,
    Fade,
    IconButton,
    List,
    ListItem,
    Modal,
    Pagination,
    Paper, TextField,
    Typography
} from "@mui/material";
import {memo, useEffect, useRef, useState} from "react";
import {ClimbingBoxLoader} from "react-spinners";
import SmartToyOutlinedIcon from '@mui/icons-material/SmartToyOutlined';
import ChatIcon from '@mui/icons-material/Chat';
import CloseIcon from '@mui/icons-material/Close';
import SecurityIcon from '@mui/icons-material/Security';
import SendIcon from '@mui/icons-material/Send';

interface TCVE {
    cve_id: string,
    published_date: string,
    score: number,
    description: string,
    articles: Array<{
        title: string,
        url: string,
    }>
}

interface message {
    type: 'bot' | 'user',
    content: string,
    timestamp: Date,
}



export const HomePage = memo(() => {

    const [searchQuery, setSearchQuery] = useState('');
    const [loading, setLoading] = useState(false);
    const [cveResults, setCveResults] = useState<Array<TCVE>>([]);
    const [error, setError] = useState('');
    const [rowPerPage, setRowPerPage] = useState<number>(10);
    const [currentPage, setCurrentPage] = useState<number>(0);

    const [openChatBot, setOpenChatBot] = useState<boolean>(false);
    const [messages, setMessages] = useState<message[]>([]);
    const [currentStreamingMessage, setCurrentStreamingMessage] = useState<string>('');
    const [inputValue, setInputValue] = useState<string>('');
    const [isLoading, setIsLoading] = useState<boolean>(false);
    const messagesEndRef = useRef<HTMLDivElement>(null);

    const scrollToBottom = () => {
        messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
    };

    useEffect(() => {
        scrollToBottom();
    }, [messages, currentStreamingMessage]);

    const handleOpenChatbot = () => {
        const [library, version] = searchQuery.split(':');
        setMessages([{
            type: 'bot',
            content: `Bonjour ! Je suis là pour vous aider à analyser les CVE de votre bibliothèque ${library} ${version && version.length > 0 ? ('v'+version) : ''}. 
        
J'ai actuellement ${cveResults.length} CVE${cveResults.length > 1 ? 's' : ''} analyser. Que souhaitez-vous savoir ?`,
            timestamp: new Date()
        }]);
        setOpenChatBot(true);
    }

    const mockCVEData:Record<string, Array<TCVE>> = {
        'express': [
            {
                cve_id: 'CVE-2024-0001',
                published_date: '2024-01-15 10:00:00',
                score: 8.2,
                description: 'Cross-site scripting vulnerability in Express.js middleware that allows remote attackers to inject arbitrary web script or HTML.',
                articles: [
                    { title: 'Express.js Security Advisory', url: 'https://security.express.js' },
                    { title: 'CVE Analysis Report', url: 'https://example.com/analysis' }
                ]
            },
            {
                cve_id: 'CVE-2023-0445',
                published_date: '2023-12-08 14:30:00',
                score: 5.8,
                description: 'Denial of service vulnerability affecting Express.js applications when handling malformed requests.',
                articles: [
                    { title: 'DoS Attack Prevention Guide', url: 'https://example.com/dos-guide' }
                ]
            },
            {
                cve_id: 'CVE-2024-0001',
                published_date: '2024-01-15 10:00:00',
                score: 8.2,
                description: 'Cross-site scripting vulnerability in Express.js middleware that allows remote attackers to inject arbitrary web script or HTML.',
                articles: [
                    { title: 'Express.js Security Advisory', url: 'https://security.express.js' },
                    { title: 'CVE Analysis Report', url: 'https://example.com/analysis' }
                ]
            },
            {
                cve_id: 'CVE-2023-0445',
                published_date: '2023-12-08 14:30:00',
                score: 5.8,
                description: 'Denial of service vulnerability affecting Express.js applications when handling malformed requests.',
                articles: [
                    { title: 'DoS Attack Prevention Guide', url: 'https://example.com/dos-guide' }
                ]
            }
        ],
        'lodash': [
            {
                cve_id: 'CVE-2024-0123',
                published_date: '2024-02-20 09:15:00',
                score: 9.1,
                description: 'Critical prototype pollution vulnerability in Lodash library allowing arbitrary code execution.',
                articles: [
                    { title: 'Lodash Prototype Pollution Fix', url: 'https://lodash.com/security' },
                    { title: 'NPM Security Alert', url: 'https://npm.security.com' }
                ]
            }
        ]
    };

    const getSeverityColor = (score:number) => {
        if (score >= 9.0) return '#f44336';
        if (score >= 7.0) return '#ff9800';
        if (score >= 4.0) return '#2196f3';
        return '#4caf50';
    };

    const getSeverityText = (score:number) => {
        if (score >= 9.0) return 'CRITIQUE';
        if (score >= 7.0) return 'ÉLEVÉ';
        if (score >= 4.0) return 'MOYEN';
        return 'FAIBLE';
    };

    const handleSearch = async () => {
        if (!searchQuery.trim()) {
            setError('Veuillez saisir un nom de librairie');
            return;
        }

        setLoading(true);
        setCurrentPage(0);
        setError('');
        setCveResults([]);

        const [library, version] = searchQuery.split(':');
        const response = await fetch("http://localhost:5000/getCve", {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                cve:[{name:library, version:version}]
            })
        });

        if(response.status == 200) {
            const json = await response.json() as any[];
            if(json.length == 0) {
                setError(`Aucune CVE trouvée pour "${searchQuery}"`);
            }else {
                const output:Array<TCVE> = [];
                json.forEach((cves:any[]) => {
                    cves.forEach((cve) => {
                        output.push({
                            cve_id: cve.cve_id,
                            description: cve.description,
                            articles: [],
                            score: cve.cvss_score,
                            published_date: cve.published_date
                        })
                    });
                });
                setCveResults(output)
            }
        } else {
            setError(`Une erreur est survenue pendant la requête.`);
        }
        setLoading(false);

    };

    const handleKeyPress = (event:any) => {
        if (event.key === 'Enter') {
            handleSearch();
        }
    };

    const handleSendMessage = async () => {
        if (!inputValue.trim() || isLoading) return;

        const userMessage:message = {
            type: 'user',
            content: inputValue,
            timestamp: new Date()
        };

        messages.push(userMessage);
        setMessages([...messages]);
        setIsLoading(true);
        setCurrentStreamingMessage('');

        try {
            const response = await fetch('http://localhost:5000/chat_cve', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    search: searchQuery,
                    cve: cveResults,
                    question: inputValue
                })
            });

            setInputValue('');

            if (!response.ok  || !response.body) {
                throw new Error('Erreur de connexion à l\'API');
            }

            const reader = response.body.getReader();
            const decoder = new TextDecoder();
            let accumulatedResponse = '';

            while (true) {
                const { done, value } = await reader.read();
                if (done) break;

                const chunk = decoder.decode(value);
                const lines = chunk.split('\n');

                for (const line of lines) {
                    if (line.startsWith('data: ')) {
                        const data = JSON.parse(line.slice(6));
                        if (data.content) {
                            accumulatedResponse += data.content;
                            setCurrentStreamingMessage(accumulatedResponse);
                        } else if (data.error) {
                            throw new Error(data.error);
                        }

                    }
                }
            }

            // Ajouter le message final complet
            const botMessage:message = {
                type: 'bot',
                content: accumulatedResponse,
                timestamp: new Date()
            };

            messages.push(botMessage);
            setMessages([...messages]);
            setCurrentStreamingMessage('');

        } catch (error) {
            console.error('Erreur:', error);
            const errorMessage:message = {
                type: 'bot',
                content: `Désolé, une erreur s'est produite : ${error}`,
                timestamp: new Date()
            };
            messages.push(errorMessage);
            setMessages([...messages]);
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div style={{
            maxWidth: '1200px',
            margin: '0 auto',
            padding: '32px 16px',
            fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif'
        }}>
            <Fade in={loading} >
                <Box sx={{
                    backgroundColor: "rgba(0,0,0,0.2)",
                    position: "absolute",
                    zIndex:"9",
                    inset:"0px 0px 0px 0px",
                    display:"flex",
                    justifyContent:"center",
                    alignItems:"center"
                }}>
                    <ClimbingBoxLoader size={30} color={"#444"}  />
                </Box>
            </Fade>
            {/* Header */}
            <div style={{ textAlign: 'center', marginBottom: '48px' }}>
                <div style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    marginBottom: '16px',
                    gap: '12px'
                }}>
                    <div style={{
                        width: '40px',
                        height: '40px',
                        backgroundColor: '#1976d2',
                        borderRadius: '50%',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        color: 'white',
                        fontSize: '20px',
                        fontWeight: 'bold'
                    }}>
                        🛡️
                    </div>
                    <h1 style={{
                        fontSize: '2.5rem',
                        fontWeight: 'bold',
                        margin: 0,
                        color: '#1a1a1a'
                    }}>
                        CVE Scanner
                    </h1>
                </div>
                <h2 style={{
                    fontSize: '1.25rem',
                    color: '#666',
                    marginBottom: '32px',
                    fontWeight: 'normal'
                }}>
                    Analysez les vulnérabilités de sécurité de vos dépendances
                </h2>

                {/* Search Section */}
                <div style={{
                    backgroundColor: 'white',
                    padding: '24px',
                    borderRadius: '12px',
                    boxShadow: '0 4px 12px rgba(0,0,0,0.1)',
                    maxWidth: '600px',
                    margin: '0 auto'
                }}>
                    <div style={{ display: 'flex', gap: '12px', marginBottom: '16px' }}>
                        <div style={{ flex: 1, position: 'relative' }}>
                            <input
                                type="text"
                                placeholder="ex: express ou express:4.18.0"
                                value={searchQuery}
                                onChange={(e) => setSearchQuery(e.target.value)}
                                onKeyPress={handleKeyPress}
                                style={{
                                    width: '100%',
                                    padding: '12px 16px 12px 40px',
                                    border: '2px solid #e0e0e0',
                                    borderRadius: '8px',
                                    fontSize: '16px',
                                    outline: 'none',
                                    transition: 'border-color 0.2s',
                                    boxSizing: 'border-box'
                                }}
                                onFocus={(e) => e.target.style.borderColor = '#1976d2'}
                                onBlur={(e) => e.target.style.borderColor = '#e0e0e0'}
                            />
                            <span style={{
                                position: 'absolute',
                                left: '12px',
                                top: '50%',
                                transform: 'translateY(-50%)',
                                color: '#666',
                                fontSize: '18px'
                            }}>
                🔍
              </span>
                        </div>
                        <button
                            onClick={handleSearch}
                            disabled={loading}
                            style={{
                                padding: '12px 24px',
                                backgroundColor: loading ? '#ccc' : '#1976d2',
                                color: 'white',
                                border: 'none',
                                borderRadius: '8px',
                                fontSize: '16px',
                                fontWeight: '500',
                                cursor: loading ? 'not-allowed' : 'pointer',
                                minWidth: '120px',
                                transition: 'background-color 0.2s'
                            }}
                        >
                            {loading ? '🔄 Analyse...' : 'Analyser'}
                        </button>
                    </div>

                    <p style={{
                        fontSize: '14px',
                        color: '#666',
                        margin: 0,
                        textAlign: 'left'
                    }}>
                        💡 Utilisez le format "librairie:version" pour spécifier une version (ex: express:4.18.0)
                    </p>
                </div>
            </div>

            {/* Error Display */}
            {error && (
                <div style={{
                    backgroundColor: '#fff3cd',
                    border: '1px solid #ffeaa7',
                    color: '#856404',
                    padding: '12px 16px',
                    borderRadius: '8px',
                    marginBottom: '24px'
                }}>
                    ⚠️ {error}
                </div>
            )}

            {/* Results Section */}
            {cveResults.length > 0 && (
                <div>
                    <h3 style={{
                        fontSize: '1.5rem',
                        marginBottom: '24px',
                        color: '#1a1a1a'
                    }}>
                        Vulnérabilités détectées ({cveResults.length})
                    </h3>

                    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px', overflowY:"auto", maxHeight:"calc(100vh - 500px)" }}>
                        {cveResults.slice(currentPage*rowPerPage, (currentPage+1)*rowPerPage).map((cve, index) => (
                            <div key={index} style={{
                                backgroundColor: 'white',
                                borderRadius: '12px',
                                padding: '24px',
                                boxShadow: '0 4px 12px rgba(0,0,0,0.1)',
                                border: `3px solid ${getSeverityColor(cve.score)}20`
                            }}>
                                <div style={{
                                    display: 'flex',
                                    justifyContent: 'space-between',
                                    alignItems: 'flex-start',
                                    marginBottom: '16px',
                                    flexWrap: 'wrap',
                                    gap: '16px'
                                }}>
                                    <div style={{ flex: 1 }}>
                                        <h4 style={{
                                            fontSize: '1.25rem',
                                            fontWeight: 'bold',
                                            margin: '0 0 8px 0',
                                            color: '#1a1a1a'
                                        }}>
                                            {cve.cve_id}
                                        </h4>
                                        <p style={{
                                            fontSize: '14px',
                                            color: '#666',
                                            margin: 0
                                        }}>
                                            Publié le: {new Date(cve.published_date).toLocaleDateString('fr-FR')}
                                        </p>
                                    </div>

                                    <div style={{
                                        backgroundColor: getSeverityColor(cve.score),
                                        color: 'white',
                                        padding: '8px 16px',
                                        borderRadius: '20px',
                                        fontSize: '14px',
                                        fontWeight: 'bold',
                                        display: 'flex',
                                        alignItems: 'center',
                                        gap: '6px'
                                    }}>
                                        ⚠️ {getSeverityText(cve.score)} ({cve.score})
                                    </div>
                                </div>

                                <p style={{
                                    fontSize: '16px',
                                    lineHeight: '1.6',
                                    color: '#333',
                                    marginBottom: '20px'
                                }}>
                                    {cve.description}
                                </p>

                                {cve.articles && cve.articles.length > 0 && (
                                    <div>
                                        <hr style={{
                                            border: 'none',
                                            borderTop: '1px solid #e0e0e0',
                                            margin: '20px 0 16px 0'
                                        }} />
                                        <div style={{
                                            display: 'flex',
                                            alignItems: 'center',
                                            marginBottom: '12px',
                                            gap: '8px'
                                        }}>
                                            <span style={{ fontSize: '16px' }}>ℹ️</span>
                                            <h5 style={{
                                                fontSize: '16px',
                                                fontWeight: '600',
                                                margin: 0,
                                                color: '#1a1a1a'
                                            }}>
                                                Articles de référence
                                            </h5>
                                        </div>
                                        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                                            {cve.articles.map((article, articleIndex) => (
                                                <a
                                                    key={articleIndex}
                                                    href={article.url}
                                                    target="_blank"
                                                    rel="noopener noreferrer"
                                                    style={{
                                                        display: 'flex',
                                                        alignItems: 'center',
                                                        gap: '8px',
                                                        color: '#1976d2',
                                                        textDecoration: 'none',
                                                        fontSize: '15px',
                                                        padding: '4px 0'
                                                    }}
                                                    onMouseOver={(e) => (e.target as HTMLElement).style.textDecoration = 'underline'}
                                                    onMouseOut={(e) => (e.target as HTMLElement).style.textDecoration = 'none'}
                                                >
                                                    <span style={{ fontSize: '14px' }}>🔗</span>
                                                    {article.title}
                                                </a>
                                            ))}
                                        </div>
                                    </div>
                                )}
                            </div>
                        ))}
                    </div>
                    <Box sx={{display:"flex", justifyContent:"center", alignItems:"center", padding:"10px"}}>
                        <Pagination
                            count={Math.ceil(cveResults.length/rowPerPage)}
                            page={currentPage+1}
                            siblingCount={0}
                            size={"medium"}

                            onChange={(evt, page) => {
                                setCurrentPage(page-1);
                            }}
                        />
                    </Box>
                </div>
            )}

            {/* Empty State */}
            {!loading && cveResults.length === 0 && !error && (
                <div style={{
                    textAlign: 'center',
                    padding: '64px 0',
                    color: '#666'
                }}>
                    <div style={{ fontSize: '80px', marginBottom: '16px' }}>🛡️</div>
                    <h3 style={{
                        fontSize: '1.25rem',
                        color: '#666',
                        fontWeight: 'normal'
                    }}>
                        Saisissez le nom d'une librairie pour commencer l'analyse
                    </h3>
                </div>
            )}
            <Fade in={searchQuery.length > 0 && cveResults.length > 0}>
                <Fab sx={{position:"fixed", right:"50px", bottom:"50px"}} size={"large"} color={"primary"} onClick={() => { handleOpenChatbot() }}>
                    <SmartToyOutlinedIcon sx={{height:"35px", width:"35px"}}/>
                </Fab>
            </Fade>
            <Modal
                open={openChatBot}
                onClose={() => {setOpenChatBot(false) }}
                closeAfterTransition
            >
                <Fade in={openChatBot}>
                    <Box sx={{
                        position: 'absolute',
                        top: '50%',
                        left: '50%',
                        transform: 'translate(-50%, -50%)',
                        width: { xs: '90%', sm: 600, md: 700 },
                        height: { xs: '80%', sm: 600 },
                        bgcolor: 'background.paper',
                        borderRadius: 2,
                        boxShadow: 24,
                        display: 'flex',
                        flexDirection: 'column',
                        overflow: 'hidden'
                    }}>
                        {/* Header */}
                        <Box sx={{
                            p: 2,
                            borderBottom: 1,
                            borderColor: 'divider',
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'space-between',
                            bgcolor: 'primary.main',
                            color: 'primary.contrastText'
                        }}>
                            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                                <ChatIcon />
                                <Typography variant="h6" component="h2">
                                    Assistant CVE
                                </Typography>
                            </Box>
                            <IconButton
                                onClick={() => { setOpenChatBot(false)}}
                                sx={{ color: 'inherit' }}
                            >
                                <CloseIcon />
                            </IconButton>
                        </Box>

                        {/* Info sur la recherche actuelle */}
                        <Box sx={{ p: 2, bgcolor: 'grey.50' }}>
                            <Typography variant="body2" color="text.secondary" gutterBottom>
                                Recherche actuelle:
                            </Typography>
                            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, flexWrap: 'wrap' }}>
                                <Chip
                                    icon={<SecurityIcon />}
                                    label={`${searchQuery.split(':')[0]} ${searchQuery.split(':').length > 1 ? ('v'+searchQuery.split(':')[1]): '' }`}
                                    color="primary"
                                    variant="outlined"
                                    size="small"
                                />
                                <Chip
                                    label={`${cveResults.length} CVE${cveResults.length > 1 ? 's' : ''}`}
                                    color="secondary"
                                    size="small"
                                />
                                {Object.entries(cveResults).slice(0, 3).map(([cveId, cve]) => (
                                    <Chip
                                        key={cveId}
                                        label={cve.cve_id}
                                        sx={{color:getSeverityColor(cve.score)}}
                                        size="small"
                                        variant="outlined"
                                    />
                                ))}
                                {cveResults.length > 3 && (
                                    <Chip
                                        label={`+${cveResults.length - 3} autres`}
                                        size="small"
                                        variant="outlined"
                                    />
                                )}
                            </Box>
                        </Box>

                        <Divider />

                        {/* Zone de messages */}
                        <Box sx={{
                            flex: 1,
                            overflow: 'auto',
                            p: 1,
                            bgcolor: 'grey.25'
                        }}>
                            <List>
                                {messages.map((message, index) => (
                                    <ListItem
                                        key={index}
                                        sx={{
                                            flexDirection: 'column',
                                            alignItems: message.type === 'user' ? 'flex-end' : 'flex-start'
                                        }}
                                    >
                                        <Paper
                                            elevation={1}
                                            sx={{
                                                p: 2,
                                                maxWidth: '80%',
                                                bgcolor: message.type === 'user' ? 'primary.main' : 'background.paper',
                                                color: message.type === 'user' ? 'primary.contrastText' : 'text.primary',
                                                borderRadius: 2,
                                                borderTopRightRadius: message.type === 'user' ? 0 : 2,
                                                borderTopLeftRadius: message.type === 'bot' ? 0 : 2
                                            }}
                                        >
                                            <Typography variant="body1" sx={{ whiteSpace: 'pre-wrap' }}>
                                                {message.content}
                                            </Typography>
                                            <Typography
                                                variant="caption"
                                                sx={{
                                                    display: 'block',
                                                    mt: 0.5,
                                                    opacity: 0.7,
                                                    textAlign: message.type === 'user' ? 'right' : 'left'
                                                }}
                                            >
                                                {message.timestamp.toLocaleTimeString()}
                                            </Typography>
                                        </Paper>
                                    </ListItem>
                                ))}

                                {/* Message en cours de streaming */}
                                {currentStreamingMessage && (
                                    <ListItem sx={{ flexDirection: 'column', alignItems: 'flex-start' }}>
                                        <Paper
                                            elevation={1}
                                            sx={{
                                                p: 2,
                                                maxWidth: '80%',
                                                bgcolor: 'background.paper',
                                                borderRadius: 2,
                                                borderTopLeftRadius: 0
                                            }}
                                        >
                                            <Typography variant="body1" sx={{ whiteSpace: 'pre-wrap' }}>
                                                {currentStreamingMessage}
                                                <Box
                                                    component="span"
                                                    sx={{
                                                        width: 2,
                                                        height: 20,
                                                        bgcolor: 'primary.main',
                                                        display: 'inline-block',
                                                        ml: 0.5,
                                                        animation: 'blink 1s infinite'
                                                    }}
                                                />
                                            </Typography>
                                        </Paper>
                                    </ListItem>
                                )}

                                {/* Indicateur de chargement */}
                                {isLoading && !currentStreamingMessage && (
                                    <ListItem sx={{ justifyContent: 'center' }}>
                                        <CircularProgress size={20} />
                                        <Typography variant="body2" sx={{ ml: 1 }}>
                                            L'assistant réfléchit...
                                        </Typography>
                                    </ListItem>
                                )}
                            </List>
                            <div ref={messagesEndRef} />
                        </Box>

                        {/* Zone de saisie */}
                        <Box sx={{
                            p: 2,
                            borderTop: 1,
                            borderColor: 'divider',
                            bgcolor: 'background.paper'
                        }}>
                            <Box sx={{ display: 'flex', gap: 1 }}>
                                <TextField
                                    fullWidth
                                    multiline
                                    maxRows={3}
                                    placeholder="Posez votre question sur les CVE..."
                                    value={inputValue}
                                    onChange={(e) => setInputValue(e.target.value)}
                                    onKeyPress={(event) => {
                                        if (event.key === 'Enter' && !event.shiftKey) {
                                            event.preventDefault();
                                            handleSendMessage();
                                        }
                                    }}
                                    disabled={isLoading}
                                    variant="outlined"
                                    size="small"
                                />
                                <Button
                                    variant="contained"
                                    onClick={handleSendMessage}
                                    disabled={!inputValue.trim() || isLoading}
                                    sx={{ minWidth: 'auto', px: 2 }}
                                >
                                    <SendIcon />
                                </Button>
                            </Box>
                            <Typography variant="caption" color="text.secondary" sx={{ mt: 1, display: 'block' }}>
                                Appuyez sur Entrée pour envoyer, Maj+Entrée pour une nouvelle ligne
                            </Typography>
                        </Box>
                    </Box>
                </Fade>
            </Modal>
        </div>
    );
});

