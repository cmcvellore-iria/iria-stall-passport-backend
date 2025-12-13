import express from "express";
import cors from "cors";

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3000;

app.get("/", (req, res) => {
  res.send("IRIA Stall Passport backend running");
});

app.listen(PORT, () => {
  console.log("Backend running on port", PORT);
});
