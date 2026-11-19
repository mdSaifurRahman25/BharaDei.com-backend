import express from 'express'; 
import cors from 'cors'; 
import 'dotenv/config'; 

const app = express(); 
const port = process.env.PORT || 5000

app.get(cors()); 
app.get(express.json()); 

app.get('/', (req, res) => {
  res.send('Hello World!')
})

app.listen(port, () => {
  console.log(`Server is successfully running at http://localhost:${port}`)
})