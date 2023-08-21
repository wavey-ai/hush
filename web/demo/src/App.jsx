import React, { useState, useEffect } from "react";

export default function App() {
  return (
    <div className="h-screen w-screen flex items-center justify-center hover:bg-black" style={{
      backgroundImage: 'linear-gradient(to right,  #f94c75, #eb429f, #ff04c7)',
    }}>
      <img src="/wavey.png" className="w-28 object-contain hover:bg-black" alt="description" />
    </div>

  );
}
